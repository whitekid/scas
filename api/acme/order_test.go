package acme

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	acmeclient "scas/client/acme"
	"scas/pkg/helper/x509x"
	"scas/pkg/testutils"
)

func TestNewOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupFixture(ctx, t)

	require.Regexp(t, `^http.+/orders/.+`, client.order.Location)
	require.NotEmpty(t, client.order.Authz)
	for _, authURI := range client.order.Authz {
		require.Regexp(t, `^http.+/authz/+`, authURI)
		authz, err := client.Authz(authURI).Get(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, authz.Challenges)
		for _, chal := range authz.Challenges {
			require.Regexp(t, `^http`, chal.URL)
		}
	}
	require.Regexp(t, `^http.+/orders/.+/finalize$`, client.order.Finalize)
	require.Empty(t, client.order.Certificate) // at first there is no certificate, until finialize order
}

func TestFinalizeOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type args struct {
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`valid`, args{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := setupFixture(ctx, t)
			authz := client.authzs[0]
			chal := authz.Challenges[0]
			require.NoError(t, client.manager.UpdateChallengeStatus(ctx, idFromURI(chal.URL), authz.ID, acmeclient.ChallengeStatusValid))

			csr := &x509.CertificateRequest{
				Subject: pkix.Name{
					SerialNumber: x509x.RandomSerial().String(),
					CommonName:   client.order.Identifiers[0].Value,
				},
			}
			finalizedOrder, err := client.Order(client.order.Finalize).Finalize(ctx, csr)
			require.Truef(t, (err != nil) == tt.wantErr, `Finalize() failed: error = %+v, wantErr = %v`, err, tt.wantErr)

			cert, err := client.Certificate(finalizedOrder.Certificate).Get(ctx)
			require.NoError(t, err)

			got, err := x509x.ParseCertificate(cert)
			require.NoError(t, err)
			require.Equal(t, csr.Subject.CommonName, got.Subject.CommonName)
			require.Equal(t, client.order.NotAfter.Time, got.NotAfter)
			require.Equal(t, client.order.NotBefore.Time, got.NotBefore)
			require.Equal(t, x509.ECDSAWithSHA256.String(), got.SignatureAlgorithm.String()) // user의 public key algorithm
			require.Equal(t, x509.ECDSA.String(), got.PublicKeyAlgorithm.String())
		})
	}
}

func TestChallengeRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupFixture(ctx, t)

	authz := testutils.Must1(client.Authz(client.order.Authz[0]).Get(ctx))
	require.NotEmpty(t, authz.Challenges)

	challengeURL := authz.Challenges[0].URL

	// get challenge resource
	{
		chal := testutils.Must1(client.Challenge(challengeURL).Get(ctx))
		require.Nil(t, chal.RetryAfter)
		require.Empty(t, chal.Error)
	}

	// request verify request
	testutils.Must(client.Challenge(challengeURL).VerifyRequest(ctx))
	time.Sleep(time.Second) // give some time to validate

	// check if challenge status updated
	{
		chal := testutils.Must1(client.Challenge(challengeURL).Get(ctx))
		require.NotNil(t, chal.RetryAfter)
		require.NotEmpty(t, chal.Error)
		require.Equal(t, "urn:ietf:params:acme:error:incorrectResponse", chal.Error.Type)
		require.Equal(t, "response received didn't match the challenge's requirements", chal.Error.Title)
		require.Containsf(t, chal.Error.Detail, "connection refused", "detail: %s", chal.Error.Detail)
		require.Equal(t, http.StatusForbidden, chal.Error.Status)
	}
}
