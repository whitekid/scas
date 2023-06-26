package testutils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp"
)

// TODO move to goxp
func Must(err error) {
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
}

// TODO move to goxp
func Must1[T any](v T, err error) T {
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
	return v
}

// TODO move to goxp
func NoError1[T1 any](t *testing.T, v goxp.Tuple2[T1, error]) T1 {
	require.NoError(t, v.V2)
	return v.V1
}
