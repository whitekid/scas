package acme

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/pkg/helper"
	"scas/pkg/helper/x509x"
	"scas/pkg/testutils"
)

type TestServer struct {
	*httptest.Server

	handler http.Handler
	server  *Server
}

func newTestServer(ctx context.Context, t *testing.T) *TestServer {
	dbname := testutils.DBName(t)
	os.RemoveAll(dbname + ".db")
	server := New("sqlite://" + dbname + ".db")

	handler := testutils.NewEndpointHandler(server)
	// TODO move to helper?
	handler.(*helper.Echo).HTTPErrorHandler = errorHandler
	ts := &TestServer{
		Server:  httptest.NewServer(handler),
		handler: handler,
	}
	go func() {
		<-ctx.Done()
		defer ts.Close()
	}()
	server.addr = ts.URL
	server.Startup(ctx)

	ts.server = server

	return ts
}

func TestScenario(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ts := newTestServer(ctx, t)

	client := testutils.Must1(acmeclient.New(ts.URL, nil))

	log.Debugf("request new account....")
	account, err := client.NewAccount(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:hello@example.com"}})
	require.NoError(t, err)

	updatedAccount, err := client.Account(account.Location).Update(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:updated@example.com"}})
	require.NoError(t, err)
	require.Equal(t, updatedAccount.Contact[0], "mailto:updated@example.com")

	notBefore := common.TimestampNow().Truncate(time.Hour*24).AddDate(0, 0, -7)
	notAfter := common.TimestampNow().Truncate(time.Hour*24).AddDate(0, 1, 0)
	order, err := client.NewOrder(ctx, &acmeclient.OrderRequest{
		Identifiers: []common.Identifier{{Type: common.IdentifierDNS, Value: "test.charlie.127.0.0.1.sslip.io"}},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
	})
	require.NoError(t, err, "request new order failed: %+v", err)
	require.Equal(t, order.Status, acmeclient.OrderStatusPending)

	// authorize
	challenges := []*acmeclient.Challenge{}
	for _, authz := range order.Authz {
		authz, err := client.Authz(authz).Get(ctx)
		require.NoError(t, err)
		require.Equal(t, acmeclient.AuthzStatusPending, authz.Status)

		challenges = append(challenges, authz.Challenges...)
	}

	challengeServer := testutils.NewChallengeServer(challenges[0].Token, client.Thumbprint())
	defer challengeServer.Close()
	u, _ := url.Parse(challengeServer.URL)
	os.Setenv("CHALLENGE_HTTP01_SERVER_PORT", u.Port())

	// request to verification challenge
	for _, challenge := range challenges {
		err := client.Challenge(challenge.URL).VerifyRequest(ctx)
		require.NoError(t, err)
	}

	for i := 0; i < 20; i++ {
		status := fx.Map(order.Authz, func(url string) acmeclient.AuthzStatus {
			authz, err := client.Authz(url).Get(ctx)
			require.NoError(t, err)
			return authz.Status

		})
		status = fx.Filter(status, func(s acmeclient.AuthzStatus) bool { return s != acmeclient.AuthzStatusValid })

		if len(status) == 0 { // all authorized
			break
		}

		time.Sleep(time.Millisecond * 100) // run again
	}

	finalizedOrder, err := client.Order(order.Finalize).Finalize(ctx, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.charlie.127.0.0.1.sslip.io",
			SerialNumber: x509x.RandSerial().String(),
		},
		DNSNames: []string{"test.charlie.127.0.0.1.sslip.io"},
	})

	require.NoError(t, err)
	require.Equal(t, acmeclient.OrderStatusValid, finalizedOrder.Status)
	require.NotEmpty(t, finalizedOrder.Certificate)

	// download certificate
	chain, err := client.Cert(finalizedOrder.Certificate).Get(ctx)
	require.NoError(t, err)
	require.NotEqual(t, 0, len(chain))
	for _, cert := range chain {
		x509cert, err := x509x.ParseCertificate(cert)
		require.NoError(t, err)
		require.Equal(t, []string{"test.charlie.127.0.0.1.sslip.io"}, x509cert.DNSNames)
		require.Equal(t, "test.charlie.127.0.0.1.sslip.io", x509cert.Subject.CommonName)
		require.Equal(t, notBefore.Time, x509cert.NotBefore)
		require.Equal(t, notAfter.Time, x509cert.NotAfter)
	}
}
