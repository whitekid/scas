package acme

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	acmeclient "scas/client/acme"
	"scas/pkg/testutils"
)

func TestNonce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := testutils.Must1(acmeclient.New(newTestServer(ctx, t).URL, nil))
	require.NotEqual(t, "", client.Nonce())
}
