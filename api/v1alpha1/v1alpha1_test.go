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
	caPool := testutils.Must1(repo.CreateCAPool(ctx, project.ID, testCAPoolName))
	rootCA := testutils.Must1(repo.CreateCertificateAuthority(ctx, project.ID, caPool.ID, &certmanager.CreateRequest{
		CommonName:   "example.com ROOT CA",
		KeyAlgorithm: x509types.ECDSA_P384,
		KeyUsage:     x509types.RootCAKeyUsage,
		ExtKeyUsage:  x509types.RootCAExtKeyUsage,
		NotAfter:     helper.AfterNow(5, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
		IsCA:         true,
	}, ""))
	subCA := testutils.Must1(repo.CreateCertificateAuthority(ctx, project.ID, caPool.ID, &certmanager.CreateRequest{
		CommonName:   "example.com CA 1",
		KeyAlgorithm: x509types.ECDSA_P256,
		KeyUsage:     x509types.SubCAKeyUsage,
		ExtKeyUsage:  x509types.SubCAExtKeyUsage,
		NotAfter:     helper.AfterNow(3, 0, 0),
		NotBefore:    helper.AfterNow(0, -0, 0),
		IsCA:         true,
	}, rootCA.ID))
	cert := testutils.Must1(repo.CreateCertificate(ctx, project.ID, caPool.ID, &certmanager.CreateRequest{
		CommonName:   testServerCN,
		Hosts:        []string{testServerCN},
		KeyAlgorithm: x509types.RSA_2048,
		KeyUsage:     x509types.ServerKeyUsage,
		ExtKeyUsage:  x509types.ServerExtKeyUsage,
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
	testCAPoolName      = "example.local"
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

	// create Pool
	caPool, err := projectSvc.Pools("").Create(ctx, &CAPool{Name: testCAPoolName})
	require.NoError(t, err)

	// create root CA
	poolSvc := projectSvc.Pools(caPool.ID)
	rootCAReq := &CertificateRequest{
		CommonName:         caPool.ID + " ROOT CA 1",
		Country:            "country",
		Organization:       "example.com org",
		OrganizationalUnit: "example.com org unit",
		StreetAddress:      "street",
		Locality:           "locality",
		Province:           "province",
		PostalCode:         "postal",
		KeyAlgorithm:       x509types.ECDSA_P384,
		KeyUsage:           x509types.RootCAKeyUsage,
		ExtKeyUsage:        x509types.RootCAExtKeyUsage,
		NotAfter:           helper.AfterNow(5, 0, 0),
		NotBefore:          helper.AfterNow(0, -1, 0),
		CRL:                fmt.Sprintf("%s/%s/capools/%s/crl", ts.URL, project.ID, caPool.ID),
	}
	newCA, err := poolSvc.CA().Create(ctx, rootCAReq)
	require.NoError(t, err)
	rootCAReq.ID = newCA.ID
	require.Equal(t, rootCAReq, newCA)

	gotCA, err := poolSvc.CA().Get(ctx, newCA.ID)
	require.NoError(t, err)
	require.Equal(t, rootCAReq, gotCA)

	// create subordinate ca, with parent
	subCAReq := &CertificateRequest{
		CommonName:   testCAPoolName + " CA",
		KeyAlgorithm: x509types.ECDSA_P256,
		KeyUsage:     x509types.SubCAKeyUsage,
		ExtKeyUsage:  x509types.SubCAExtKeyUsage,
		NotAfter:     helper.AfterNow(3, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
		CAID:         newCA.ID,
		CRL:          rootCAReq.CRL,
	}
	subCA, err := poolSvc.CA().Create(ctx, subCAReq)
	require.NoError(t, err)

	subCAReq.ID = subCA.ID
	subCAReq.NotAfter = subCA.NotAfter
	require.Equal(t, subCAReq, subCA)

	// create server certificate
	newCert, err := poolSvc.Certificates().Create(ctx, &CertificateRequest{
		CommonName:   testServerCN,
		Hosts:        []string{testServerCN},
		KeyAlgorithm: x509types.RSA_2048,
		KeyUsage:     x509types.ServerKeyUsage,
		ExtKeyUsage:  x509types.ServerExtKeyUsage,
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
	cert, err := poolSvc.Certificates().Get(ctx, newCert.ID)
	require.NoError(t, err)
	require.Equal(t, newCert, cert)

	// test tls
	require.NoError(t, testutils.TestTLSServer(ctx, cert.TlsCrtPEM, cert.TlsKeyPEM, cert.ChainCrtPEM, testServerCN, http.StatusOK))

	// create new certificate for revoke
	revokedCertReq := &CertificateRequest{
		CommonName:   testRevokedServerCN,
		Hosts:        []string{testRevokedServerCN},
		KeyAlgorithm: x509types.RSA_2048,
		NotAfter:     helper.AfterNow(1, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
		CAID:         subCA.ID,
	}
	certForRevoke, err := poolSvc.Certificates().Create(ctx, revokedCertReq)
	require.NoError(t, err)

	// revoke current certificate
	err = poolSvc.Certificates().Revoke(ctx, certForRevoke.ID, x509types.RevokeSuperseded)
	require.NoError(t, err)

	revokedCert, err := poolSvc.Certificates().Get(ctx, certForRevoke.ID)
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
		{"valid: cn", args{&CertificateRequest{CommonName: "cn", KeyAlgorithm: x509types.ECDSA_P256, NotBefore: notBefore, NotAfter: notAfter}}, false},
		{"valid: crl", args{&CertificateRequest{CommonName: "cn", CRL: ts.URL, KeyAlgorithm: x509types.ECDSA_P256, NotBefore: notBefore, NotAfter: notAfter}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			projectList := testutils.Must1(v1alpha1API.Projects("").List(ctx))
			projectID := projectList.Items[0].ID

			pools := testutils.Must1(v1alpha1API.Projects(projectID).Pools("").List(ctx))

			got, err := v1alpha1API.Projects(projectID).Pools(pools.Items[0].ID).CA().Create(ctx, tt.args.req)
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

	pools := testutils.Must1(v1alpha1API.Projects(projectID).Pools("").List(ctx))

	r := testutils.Must1(repo.ListCertificate(ctx, projectID, pools.Items[0].ID, certmanager.CertificateListOpt{Status: common.StatusActive}))
	require.NotEqual(t, 0, len(r))
	testServerCertID := r[0].ID

	poolAPI := v1alpha1.New(ts.URL).Projects(projectID).Pools(pools.Items[0].ID)

	certList, err := poolAPI.Certificates().List(ctx)
	require.NoError(t, err)
	require.NotEqual(t, 0, len(certList.Items))

	certService := poolAPI.Certificates()
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

	pools := testutils.Must1(v1alpha1API.Projects(projectID).Pools("").List(ctx))

	r := testutils.Must1(repo.ListCertificate(ctx, projectID, pools.Items[0].ID, certmanager.CertificateListOpt{Status: common.StatusActive}))
	require.NotEqual(t, 0, len(r))
	testServerCertID := r[0].ID

	poolAPI := v1alpha1.New(ts.URL).Projects(projectID).Pools(pools.Items[0].ID)
	leafAPI := poolAPI.Certificates()
	cert, err := leafAPI.Get(ctx, testServerCertID)
	require.NoError(t, err)
	require.Equal(t, testServerCertID, cert.ID)
	require.NotEqual(t, "", cert.CAID)

	err = leafAPI.Revoke(ctx, testServerCertID, x509types.RevokeSuperseded)
	require.NoError(t, err)

	crlPEMBytes, err := poolAPI.GetCRL(ctx)
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

			_, err := v1alpha1.New(ts.URL).Projects(projectID).Pools(testCAPoolName).Certificates().Get(ctx, tt.args.ID)
			require.Falsef(t, (err != nil) != tt.wantErr, "v1Alpha1API.getCertificate() error = %v, wantErr %v", err, tt.wantErr)

			if tt.wantCode > 0 {
				var e *v1alpha1.HttpError
				require.ErrorAs(t, err, &e)
				require.Equal(t, tt.wantCode, e.Code())
			}
		})
	}
}

func Test_v1Alpha1API_createCAPool(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name     string
		args     args
		wantErr  bool
		wantCode int
	}{
		{"duplicate", args{testCAPoolName}, true, http.StatusConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			ts, _ := newTestServerWithFixture(ctx, t)

			v1alpha1API := v1alpha1.New(ts.URL)
			projectList := testutils.Must1(v1alpha1API.Projects("").List(ctx))
			projectID := projectList.Items[0].ID

			_, err := v1alpha1.New(ts.URL).Projects(projectID).Pools("").Create(ctx, &v1alpha1.CAPool{Name: testCAPoolName})

			require.Falsef(t, (err != nil) != tt.wantErr, "v1Alpha1API.createCAPool() error = %v, wantErr %v", err, tt.wantErr)

			if tt.wantCode > 0 {
				var e *v1alpha1.HttpError
				require.ErrorAs(t, err, &e)
				require.Equal(t, tt.wantCode, e.Code())
			}
		})
	}
}
