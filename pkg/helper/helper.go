package helper

import (
	"context"
	"crypto"
	"strconv"
	"time"

	"github.com/whitekid/goxp/fx"
)

func AtoiDef[T fx.Int](s string, def T) T {
	value, err := strconv.Atoi(s)
	if err != nil {
		return def
	}

	return T(value)
}

func ParseBoolDef(s string, def bool) bool {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return def
	}
	return v
}

func After(ctx context.Context, d time.Duration, fn func()) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(d):
		fn()
	}
}

func SHA256Sum(data []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(data)
	return h.Sum(nil)
}
