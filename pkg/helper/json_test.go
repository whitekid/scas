package helper

import (
	"context"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExecute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := Execute("ls /not-found").Shell().Dir("").Do(ctx)
	require.Error(t, err)
	require.IsType(t, &exec.ExitError{}, err)
}
