package acme

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"scas/client/acme"
	"scas/client/common"
	"scas/client/common/x509types"
	"scas/pkg/helper/x509x"
	"scas/pkg/testutils"
)

func TestGetCert(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupFixture(ctx, t)

	// verify challenges
	authz := testutils.Must1(client.Authz(client.order.Authz[0]).Get(ctx))
	require.NoError(t, client.manager.UpdateChallengeStatus(ctx, idFromURI(authz.Challenges[0].URL), idFromURI(client.order.Authz[0]), acme.ChallengeStatusValid))
	order := testutils.Must1(client.Order(client.order.Finalize).Finalize(ctx, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.charlie.127.0.0.1.sslip.io",
			SerialNumber: x509x.RandomSerial().String(),
		},
		DNSNames: []string{"test.charlie.127.0.0.1.sslip.io"},
	}))

	type args struct {
		certURI string
	}
	tests := [...]struct {
		name       string
		args       args
		wantErr    bool
		wantStatus int
	}{
		{`valid`, args{order.Certificate}, false, 0},
		{`not found`, args{order.Certificate + "not found"}, true, http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.Certificate(tt.args.certURI).Get(ctx)
			require.Truef(t, (err != nil) == tt.wantErr, `Certificate.Get() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			if tt.wantErr {
				var p *common.ProblemDetail
				require.ErrorAs(t, err, &p)
				require.Equal(t, tt.wantStatus, p.Status)
				return
			}

			require.NotEmpty(t, got)
			require.Contains(t, string(got), "-----BEGIN ", "cert must be PEM format")
			cert, err := x509x.ParseCertificate(got)
			require.NoError(t, err)
			require.NotEmpty(t, cert)
		})
	}

}

func TestCertRevocation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupFixture(ctx, t)

	// verify challenges
	authz := testutils.Must1(client.Authz(client.order.Authz[0]).Get(ctx))
	require.NoError(t, client.manager.UpdateChallengeStatus(ctx, idFromURI(authz.Challenges[0].URL), idFromURI(client.order.Authz[0]), acme.ChallengeStatusValid))
	order := testutils.Must1(client.Order(client.order.Finalize).Finalize(ctx, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.charlie.127.0.0.1.sslip.io",
			SerialNumber: x509x.RandomSerial().String(),
		},
		DNSNames: []string{"test.charlie.127.0.0.1.sslip.io"},
	}))

	cert := testutils.Must1(client.Certificate(order.Certificate).Get(ctx))
	require.NotEmpty(t, cert)

	err := client.Certificate(order.Certificate).Revoke(ctx, cert, x509types.RevokeUnspecified)
	require.NoError(t, err)

	_, err = client.Certificate(order.Certificate).Get(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already been revoked")
}
