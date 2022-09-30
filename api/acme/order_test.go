package acme

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"scas/acme/manager"
	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/pkg/testutils"
)

type fixture struct {
	*acmeclient.Client
	manager *manager.Manager
	acct    *acmeclient.Account
	order   *acmeclient.Order
}

func setupFixture(ctx context.Context, t *testing.T) *fixture {
	priv := generateKey(t)

	server := newTestServer(ctx, t)
	client := testutils.Must1(acmeclient.New(server.URL, priv))

	acct := testutils.Must1(client.NewAccount(ctx, &acmeclient.AccountRequest{Contact: []string{"mailto:hello@example.com"}}))
	order := testutils.Must1(client.NewOrder(ctx, &acmeclient.OrderRequest{
		Identifiers: []common.Identifier{{Type: common.IdentifierDNS, Value: "test.charlie.127.0.0.1.sslip.io"}},
		NotBefore:   common.TimestampNow().Truncate(time.Hour*24).AddDate(0, 0, -7),
		NotAfter:    common.TimestampNow().Truncate(time.Hour*24).AddDate(0, 1, 0),
	}))

	return &fixture{
		Client:  client,
		manager: server.server.manager,
		acct:    acct,
		order:   order,
	}
}

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
