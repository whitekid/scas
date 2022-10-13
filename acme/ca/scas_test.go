package ca

import (
	"context"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"scas/api/v1alpha1"
	"scas/certmanager"
	"scas/certmanager/provider"
	"scas/certmanager/store"
	"scas/client/common/x509types"
	scasclient "scas/client/v1alpha1"
	"scas/pkg/helper"
	"scas/pkg/helper/x509x"
	"scas/pkg/testutils"
)

func newFixture(ctx context.Context, t *testing.T, dbURL string) *fixture {
	repo := certmanager.New(provider.Native(), store.NewSQL(dbURL))
	ts := httptest.NewServer(testutils.NewEndpointHandler(v1alpha1.NewWithRepository(repo)))
	go func() {
		<-ctx.Done()
		ts.Close()
	}()

	client := scasclient.New(ts.URL)

	return &fixture{
		url:    ts.URL,
		client: client,
	}
}

type fixture struct {
	url    string
	client *scasclient.Client
}

func TestSCAS(t *testing.T) {
	testutils.ForOneSQLDriver(t, "sqlite", func(t *testing.T, dbURL string, reset func()) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		fixture := newFixture(ctx, t, dbURL)

		proj, err := fixture.client.Projects("").Create(ctx, &scasclient.Project{Name: "test project"})
		require.NoError(t, err)

		pool, err := fixture.client.Projects(proj.ID).Pools("").Create(ctx, &scasclient.CAPool{Name: "test pool"})
		require.NoError(t, err)

		// create root ca
		// TODO CA()의 용법이 Project(), Pool()의 용법과 다르네...
		ca, err := fixture.client.Projects(proj.ID).Pools(pool.ID).CA().Create(ctx, &scasclient.CertificateRequest{
			CommonName:   "root CA",
			KeyAlgorithm: x509types.ECDSA_P256,
			KeyUsage:     x509types.RootCAKeyUsage,
			ExtKeyUsage:  x509types.RootCAExtKeyUsage,
			NotAfter:     helper.AfterNow(5, 1, 0).Truncate(time.Minute),
			NotBefore:    helper.AfterNow(0, -1, 0).Truncate(time.Minute),
		})
		require.NoError(t, err)

		subCa, err := fixture.client.Projects(proj.ID).Pools(pool.ID).CA().Create(ctx, &scasclient.CertificateRequest{
			CommonName:   "Subordinate CA",
			KeyAlgorithm: x509types.ECDSA_P256,
			KeyUsage:     x509types.SubCAKeyUsage,
			ExtKeyUsage:  x509types.SubCAExtKeyUsage,
			NotAfter:     helper.AfterNow(3, 0, 0),
			NotBefore:    helper.AfterNow(0, -1, 0),
			CAID:         ca.ID,
		})
		require.NoError(t, err)

		scas := NewSCAS(fixture.url, proj.ID, pool.ID, subCa.ID).(*scasImpl)
		req := &CreateRequest{
			SerialNumber: x509x.RandomSerial(),
			// TODO Issuer
			// TODO CAID
			KeyAlgorithm: x509types.ECDSA_P256,
			Subject: pkix.Name{
				CommonName: "test.charlie.127.0.0.1.sslip.io",
			},
			DNSNames:    []string{"test.charlie.127.0.0.1.sslip.io"},
			NotAfter:    helper.AfterNow(1, 0, 0),
			NotBefore:   helper.AfterNow(0, -1, 0),
			KeyUsage:    x509types.ServerKeyUsage,
			ExtKeyUsage: x509types.ServerExtKeyUsage,
		}
		certPEM, keyPEM, chainPEM, err := scas.CreateCertificate(ctx, req)
		require.NoError(t, err)
		require.NotEmpty(t, certPEM)

		certs, err := x509x.ParseCertificateChain(chainPEM)
		require.NoError(t, err)
		require.Equal(t, 2, len(certs), "need 2 certs with chain: root, subordinate, leaf, but got %d", len(certs))

		x509cert, err := x509x.ParseCertificate(certPEM)
		require.NoError(t, err)

		require.Equal(t, req.SerialNumber, x509cert.SerialNumber)
		require.Equal(t, req.KeyAlgorithm.ToX509SignatureAlgorithm(), x509cert.SignatureAlgorithm)
		require.Equal(t, req.Subject.CommonName, x509cert.Subject.CommonName)
		require.Equal(t, req.DNSNames, x509cert.DNSNames)
		require.Equal(t, req.NotAfter, x509cert.NotAfter, "NotAfter mismatch")
		require.Equal(t, req.NotBefore, x509cert.NotBefore, "NotBefore mistmatch")
		require.Equal(t, req.KeyUsage, x509cert.KeyUsage)
		require.Equal(t, req.ExtKeyUsage, x509cert.ExtKeyUsage)
		require.False(t, x509cert.IsCA)

		priv, err := x509x.ParsePrivateKey(keyPEM)
		require.NoError(t, err)
		_ = priv
	})
}
