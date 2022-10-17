package helper

import (
	"context"
	"crypto"
	"hash"
	"strconv"
	"time"

	"github.com/lithammer/shortuuid/v4"
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

func SHA256Sum(data []byte) []byte         { return Hash(crypto.SHA256.New(), data) }
func Hash(h hash.Hash, data []byte) []byte { h.Write(data); return h.Sum(nil) }
func NewID() string                        { return shortuuid.New() }
