package repository

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/certmanager/provider"
	"scas/certmanager/store"
	"scas/certmanager/types"
	"scas/client/common"
	"scas/client/common/x509types"
	"scas/pkg/helper"
	"scas/pkg/helper/x509x"
	"scas/pkg/testutils"
)

const (
	testProjectName = "project #1"
	testPoolName    = "example.local"
	testCAName      = "example.local"
	testCAHosts     = "example.local"
	testRootCACN    = "example.local Root CA"
	testSubCACN     = "example.local CA 1"
	testServerCN    = "server.example.local.127.0.0.1.sslip.io"
)

func TestRepository(t *testing.T) {
	type args struct {
		dsn string
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`sqlite`, args{"sqlite://test.db"}, false},
		// TODO: testing mysql, postgredql
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testRepositoryWithDBURL(t, tt.args.dsn)
		})
	}
}

func TestRepositorySQLite(t *testing.T) { testRepositoryWithDBURL(t, "sqlite://test.db") }

func testRepositoryWithDBURL(t *testing.T, dbURL string) {
	if u, err := url.Parse(dbURL); err == nil && strings.HasPrefix(u.Scheme, "sqlite") {
		os.Remove(u.Hostname())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	repo := New(provider.Native(), store.NewSQL(dbURL))
	project, err := repo.CreateProject(ctx, testProjectName)
	require.NoError(t, err)

	caPool, err := repo.CreateCAPool(ctx, project.ID, testPoolName)
	require.NoError(t, err)

	// create root ca
	rootCA, err := repo.CreateCertificateAuthority(ctx, project.ID, caPool.ID, &provider.CreateRequest{
		CommonName:   testRootCACN,
		KeyAlgorithm: x509types.ECDSA_P384,
		IsCA:         true,
		NotAfter:     helper.AfterNow(5, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
	}, "")
	require.NoError(t, err)
	dumpCA(t, rootCA)

	// create subordinate ca
	subCA, err := repo.CreateCertificateAuthority(ctx, project.ID, caPool.ID, &provider.CreateRequest{
		CommonName:   testSubCACN,
		KeyAlgorithm: x509types.ECDSA_P256,
		IsCA:         true,
		Hosts:        []string{testCAHosts},
		NotAfter:     helper.AfterNow(3, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
	}, rootCA.ID)
	require.NoError(t, err)
	dumpCA(t, subCA)

	serverCert, err := repo.CreateCertificate(ctx, project.ID, caPool.ID, &provider.CreateRequest{
		CommonName:   testServerCN,
		KeyAlgorithm: x509types.RSA_4096,
		Hosts:        []string{testServerCN}, // server cn is dns name
		NotAfter:     helper.AfterNow(1, 0, 0),
		NotBefore:    helper.AfterNow(0, -1, 0),
	}, subCA.ID)
	require.NoError(t, err)
	require.NotEqual(t, 0, len(serverCert.Chain), "empty chain...")

	dumpCert(t, serverCert)
	require.NoError(t, testutils.TestTLSServer(ctx, serverCert.Cert, serverCert.Key, serverCert.Chain, testServerCN, http.StatusOK))

	pools := testutils.Must1(repo.ListCAPool(ctx, project.ID, store.CAPoolListOpt{}))

	renewedCert, err := repo.RenewCertificate(ctx, project.ID, pools[0].ID, serverCert.ID)
	require.NoError(t, err)
	require.NotEqual(t, serverCert.ID, renewedCert.ID)
	require.NotEqual(t, serverCert, renewedCert)

	revokedCert, err := repo.RevokeCertificate(ctx, project.ID, caPool.ID, serverCert.ID, x509types.RevokeUnspecified)
	require.NoError(t, err)
	require.Equal(t, common.StatusRevoked, revokedCert.Status)
	require.False(t, revokedCert.RevokedAt.IsZero())
	revokedX509Cert := testutils.Must1(x509x.ParseCertificate(revokedCert.Cert))

	crlBytes, err := repo.GetCRL(ctx, project.ID, caPool.ID)
	require.NoError(t, err)
	revocationList, err := x509.ParseRevocationList(crlBytes)
	require.NoError(t, err)

	require.Equal(t, revocationList.Number, big.NewInt(1))
	require.True(t, revocationList.NextUpdate.After(time.Now()), "%s", revocationList.NextUpdate)
	require.Contains(t, fx.Map(revocationList.RevokedCertificates, func(x pkix.RevokedCertificate) *big.Int { return x.SerialNumber }), revokedX509Cert.SerialNumber)
}

func dumpCA(t *testing.T, cert *types.CertificateAuthority) {
	caCert := testutils.Must1(x509x.ParseCertificate(cert.Cert))
	log.Debugf("CN: %s ======================", caCert.Subject.CommonName)
	log.Debugf("serial: %s, keyid=%x", caCert.SerialNumber, caCert.SubjectKeyId)
	log.Debugf("issuer: %s", caCert.Issuer.CommonName)
	log.Debugf("notAfter: %s", caCert.NotAfter)
	log.Debugf("notBefore: %s", caCert.NotBefore)
}

func dumpCert(t *testing.T, cert *types.Certificate) {
	serverCert := testutils.Must1(x509x.ParseCertificate(cert.Cert))
	log.Debugf("CN: %s ======================", serverCert.Subject.CommonName)
	log.Debugf("serial: %s, keyid=%x", serverCert.SerialNumber, serverCert.SubjectKeyId)
	log.Debugf("issuer: %s", serverCert.Issuer.CommonName)
	log.Debugf("signature: %x", serverCert.Signature)
	log.Debugf("notAfter: %s", serverCert.NotAfter)
	log.Debugf("notBefore: %s", serverCert.NotBefore)

	require.NotNil(t, cert.Chain)
	chain, err := x509x.ParseCertificateChain(cert.Chain)
	require.NoError(t, err)
	log.Debugf("chain.....:")
	for _, cert := range chain {
		log.Debugf("\tserial: %s,\tcn=%s,\tissuer=%s,\tissuer.serial=%s", cert.SerialNumber, cert.Subject.CommonName, cert.Issuer.CommonName, cert.Issuer.SerialNumber)
		log.Debugf("\tpublic key: %v", cert.PublicKey)
	}
}

func Test_repoImpl_updateCRL(t *testing.T) {
	os.Remove("test.db")
	repo := New(provider.Native(), store.NewSQL("sqlite://test.db")).(*repoImpl)

	c := repo.CRLUpdateChecker()
	defer close(c)

	// update CRL every seconds
	for i := 0; i < 5; i++ {
		<-time.After(time.Second)
		c <- struct{}{}
	}

	require.False(t, repo.lastCRLUpdateChecked.IsZero())
}
