package v1alpha1

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp/log"

	"scas/certmanager"
	"scas/certmanager/provider"
	"scas/certmanager/store"
	"scas/client/common"
	"scas/client/common/x509types"
	"scas/client/v1alpha1"
	"scas/pkg/helper"
	"scas/pkg/testutils"
)

func newTestServer(ctx context.Context, t *testing.T) *httptest.Server {
	testdb := testutils.DBName(t.Name())
	os.RemoveAll(testdb + ".db")

	repo := certmanager.New(provider.Native(), store.NewSQL("sqlite://"+testdb+".db"))
	ts := httptest.NewServer(testutils.NewEndpointHandler(NewWithRepository(repo)))
	go func() {
		<-ctx.Done()
		ts.Close()
	}()
	return ts
}

func newTestServerWithFixture(ctx context.Context, t *testing.T) (*httptest.Server, *TestRepo) {
	testdb := testutils.DBName(t.Name())
	os.RemoveAll(testdb + ".db")

	repo := certmanager.New(provider.Native(), store.NewSQL("sqlite://"+testdb+".db"))

	// setup fixture
	project := testutils.Must1(repo.CreateProject(ctx, testProjectName))
	rootCA := testutils.Must1(repo.CreateCertificateAuthority(ctx, project.ID, &certmanager.CreateRequest{
		CommonName:   "example.com ROOT CA",
		KeyAlgorithm: x509.ECDSAWithSHA384,
		KeyUsage:     x509types.KeyUsageRootCA,
		ExtKeyUsage:  x509types.ExtKeyUsageRootCA,
		NotAfter:     helper.AfterNow(5, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
		IsCA:         true,
	}, ""))
	subCA := testutils.Must1(repo.CreateCertificateAuthority(ctx, project.ID, &certmanager.CreateRequest{
		CommonName:   "example.com CA 1",
		KeyAlgorithm: x509.ECDSAWithSHA384,
		KeyUsage:     x509types.KeyUsageSubCA,
		ExtKeyUsage:  x509types.ExtKeyUsageSubCA,
		NotAfter:     helper.AfterNow(3, 0, 0),
		NotBefore:    helper.AfterNow(0, -0, 0),
		IsCA:         true,
	}, rootCA.ID))
	cert := testutils.Must1(repo.CreateCertificate(ctx, project.ID, &certmanager.CreateRequest{
		CommonName:   testServerCN,
		Hosts:        []string{testServerCN},
		KeyAlgorithm: x509.ECDSAWithSHA256,
		KeyUsage:     x509types.KeyUsageServer,
		ExtKeyUsage:  x509types.ExtKeyUsageServer,
		NotAfter:     helper.AfterNow(1, 0, 0),
		NotBefore:    helper.AfterNow(0, -0, 0),
	}, subCA.ID))
	_ = cert

	ts := httptest.NewServer(testutils.NewEndpointHandler(NewWithRepository(repo)))
	go func() {
		<-ctx.Done()
		ts.Close()
	}()

	log.Debugf("========================== end of fixture ==========================")
	return ts, &TestRepo{repo}
}

type TestRepo struct {
	certmanager.Interface
}

var (
	testProjectName     = "scas project"
	testServerCN        = "server.example.local.127.0.0.1.sslip.io"
	testRevokedServerCN = "revoked.example.local.127.0.0.1.sslip.io"
)

// TestScenario test and build cert fixture data for other tests
func TestScenario(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ts := newTestServer(ctx, t)

	// create project
	v1alpha1Svc := v1alpha1.New(ts.URL)
	project, err := v1alpha1Svc.Projects("").Create(ctx, &Project{Name: testProjectName})
	require.NoError(t, err)
	projectSvc := v1alpha1Svc.Projects(project.ID)

	// create root CA
	rootCAReq := &CertificateRequest{
		CommonName:         "ROOT CA 1",
		Country:            []string{"country"},
		Organization:       []string{"example.com org"},
		OrganizationalUnit: []string{"example.com org unit"},
		StreetAddress:      []string{"street"},
		Locality:           []string{"locality"},
		Province:           []string{"province"},
		PostalCode:         []string{"postal"},
		KeyAlgorithm:       x509.ECDSAWithSHA384,
		KeyUsage:           x509types.KeyUsageRootCA,
		ExtKeyUsage:        x509types.ExtKeyUsageRootCA,
		NotAfter:           helper.AfterNow(5, 0, 0),
		NotBefore:          helper.AfterNow(0, -1, 0),
		CRL:                fmt.Sprintf("%s/%s/crl", ts.URL, project.ID),
	}
	newCA, err := projectSvc.CA().Create(ctx, rootCAReq)
	require.NoError(t, err)
	rootCAReq.ID = newCA.ID
	require.Equal(t, rootCAReq, newCA)

	gotCA, err := projectSvc.CA().Get(ctx, newCA.ID)
	require.NoError(t, err)
	require.Equal(t, rootCAReq, gotCA)

	// create subordinate ca, with parent
	subCAReq := &CertificateRequest{
		CommonName:   " CA",
		KeyAlgorithm: x509.ECDSAWithSHA384,
		KeyUsage:     x509types.KeyUsageSubCA,
		ExtKeyUsage:  x509types.ExtKeyUsageSubCA,
		NotAfter:     helper.AfterNow(3, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
		CAID:         newCA.ID,
		CRL:          rootCAReq.CRL,
	}
	subCA, err := projectSvc.CA().Create(ctx, subCAReq)
	require.NoError(t, err)

	subCAReq.ID = subCA.ID
	subCAReq.NotAfter = subCA.NotAfter
	require.Equal(t, subCAReq, subCA)

	// create server certificate
	newCert, err := projectSvc.Certificates().Create(ctx, &CertificateRequest{
		CommonName:   testServerCN,
		Hosts:        []string{testServerCN},
		KeyAlgorithm: x509.ECDSAWithSHA384,
		KeyUsage:     x509types.KeyUsageServer,
		ExtKeyUsage:  x509types.ExtKeyUsageServer,
		NotAfter:     helper.AfterNow(1, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
		CAID:         subCA.ID,
	})
	require.NoError(t, err)
	require.Equal(t, common.StatusActive, newCert.Status)
	require.Equal(t, subCA.ID, newCert.CAID)
	require.NotNil(t, newCert.TlsCrtPEM)
	require.NotNil(t, newCert.TlsKeyPEM)
	require.NotNil(t, newCert.ChainCrtPEM)

	// get server certficate
	cert, err := projectSvc.Certificates().Get(ctx, newCert.ID)
	require.NoError(t, err)
	require.Equal(t, newCert, cert)

	// test tls
	require.NoError(t, testutils.TestTLSServer(ctx, cert.TlsCrtPEM, cert.TlsKeyPEM, cert.ChainCrtPEM, testServerCN, http.StatusOK))

	// create new certificate for revoke
	revokedCertReq := &CertificateRequest{
		CommonName:   testRevokedServerCN,
		Hosts:        []string{testRevokedServerCN},
		KeyAlgorithm: x509.ECDSAWithSHA384,
		NotAfter:     helper.AfterNow(1, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
		CAID:         subCA.ID,
	}
	certForRevoke, err := projectSvc.Certificates().Create(ctx, revokedCertReq)
	require.NoError(t, err)

	// revoke current certificate
	err = projectSvc.Certificates().Revoke(ctx, certForRevoke.ID, x509types.RevokeSuperseded)
	require.NoError(t, err)

	revokedCert, err := projectSvc.Certificates().Get(ctx, certForRevoke.ID)
	require.NoError(t, err)
	require.Equal(t, common.StatusRevoked, revokedCert.Status)
}

func Test_v1Alpha1API_createCA(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ts, _ := newTestServerWithFixture(ctx, t)
	v1alpha1API := v1alpha1.New(ts.URL)

	notAfter := helper.AfterNow(5, 0, 0)
	notBefore := helper.AfterNow(0, -1, 0)

	type args struct {
		req *CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"empty request", args{&CertificateRequest{}}, true},
		{"valid: cn", args{&CertificateRequest{CommonName: "cn", KeyAlgorithm: x509.ECDSAWithSHA384, NotBefore: notBefore, NotAfter: notAfter}}, false},
		{"valid: crl", args{&CertificateRequest{CommonName: "cn", CRL: ts.URL, KeyAlgorithm: x509.ECDSAWithSHA384, NotBefore: notBefore, NotAfter: notAfter}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			projectList := testutils.Must1(v1alpha1API.Projects("").List(ctx))
			projectID := projectList.Items[0].ID

			got, err := v1alpha1API.Projects(projectID).CA().Create(ctx, tt.args.req)
			require.Falsef(t, (err != nil) != tt.wantErr, "v1Alpha1API.createCA() error = %v, wantErr %v", err, tt.wantErr)
			if tt.wantErr {
				return
			}

			require.NotEqual(t, "", got.ID)
			tt.args.req.ID = got.ID

			require.Equal(t, tt.args.req, got)
		})
	}
}

func TestRenewal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ts, repo := newTestServerWithFixture(ctx, t)

	v1alpha1API := v1alpha1.New(ts.URL)
	projectList := testutils.Must1(v1alpha1API.Projects("").List(ctx))
	projectID := projectList.Items[0].ID

	r := testutils.Must1(repo.ListCertificate(ctx, projectID, certmanager.CertificateListOpt{Status: common.StatusActive}))
	require.NotEqual(t, 0, len(r))
	testServerCertID := r[0].ID

	projAPI := v1alpha1.New(ts.URL).Projects(projectID)

	certList, err := projAPI.Certificates().List(ctx)
	require.NoError(t, err)
	require.NotEqual(t, 0, len(certList.Items))

	certService := projAPI.Certificates()
	updatedCert, err := certService.Renewal(ctx, testServerCertID)
	require.NoError(t, err)
	require.NotEqual(t, "", updatedCert.ID)

	got, err := certService.Get(ctx, updatedCert.ID)
	require.NoError(t, err)
	require.NoError(t, testutils.TestTLSServer(ctx, got.TlsCrtPEM, got.TlsKeyPEM, got.ChainCrtPEM, testServerCN, http.StatusOK))
}

func TestRevoke(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ts, repo := newTestServerWithFixture(ctx, t)

	v1alpha1API := v1alpha1.New(ts.URL)
	projectList := testutils.Must1(v1alpha1API.Projects("").List(ctx))
	projectID := projectList.Items[0].ID

	r := testutils.Must1(repo.ListCertificate(ctx, projectID, certmanager.CertificateListOpt{Status: common.StatusActive}))
	require.NotEqual(t, 0, len(r))
	testServerCertID := r[0].ID

	projAPI := v1alpha1.New(ts.URL).Projects(projectID)
	leafAPI := projAPI.Certificates()
	cert, err := leafAPI.Get(ctx, testServerCertID)
	require.NoError(t, err)
	require.Equal(t, testServerCertID, cert.ID)
	require.NotEqual(t, "", cert.CAID)

	err = leafAPI.Revoke(ctx, testServerCertID, x509types.RevokeSuperseded)
	require.NoError(t, err)

	crlPEMBytes, err := projAPI.GetCRL(ctx)
	require.NoError(t, err)
	require.NotEqual(t, 0, len(crlPEMBytes))

	crl, err := x509.ParseRevocationList(crlPEMBytes)
	require.NoError(t, err)
	require.NotEqual(t, 0, len(crl.RevokedCertificates))
}

func Test_v1Alpha1API_getCertificate(t *testing.T) {
	type args struct {
		ID string
	}
	tests := []struct {
		name     string
		args     args
		wantErr  bool
		wantCode int
	}{
		{"not found", args{"not-found"}, true, http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			ts, _ := newTestServerWithFixture(ctx, t)

			v1alpha1API := v1alpha1.New(ts.URL)
			projectList := testutils.Must1(v1alpha1API.Projects("").List(ctx))
			projectID := projectList.Items[0].ID

			_, err := v1alpha1.New(ts.URL).Projects(projectID).Certificates().Get(ctx, tt.args.ID)
			require.Falsef(t, (err != nil) != tt.wantErr, "v1Alpha1API.getCertificate() error = %v, wantErr %v", err, tt.wantErr)

			if tt.wantCode > 0 {
				var e *v1alpha1.HttpError
				require.ErrorAs(t, err, &e)
				require.Equal(t, tt.wantCode, e.Code())
			}
		})
	}
}
