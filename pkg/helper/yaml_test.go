package helper

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteYAMLToFile(t *testing.T) {
	f, err := os.CreateTemp("", "scas-*.yaml")
	require.NoError(t, err)
	f.Close()
	defer func() { os.Remove(f.Name()) }()

	x := &struct {
		Message string
	}{
		Message: "hello world",
	}

	require.NoError(t, WriteYAMLToFile(f.Name(), x))
}
