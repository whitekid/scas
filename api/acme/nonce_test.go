package acme

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNonce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := setupFixture(ctx, t)

	require.NotEqual(t, "", client.Nonce())
}
