package helper

import (
	"crypto"
	"hash"
	"strconv"

	"github.com/lithammer/shortuuid/v4"
	"golang.org/x/exp/constraints"
)

// depreciated: use goxp
func AtoiDef[T constraints.Integer](s string, defValue T) T {
	value, err := strconv.Atoi(s)
	if err != nil {
		return defValue
	}

	return T(value)
}

// depreciated: use goxp
func ParseBoolDef(s string, def bool) bool {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return def
	}
	return v
}

func SHA256Sum(data []byte) []byte         { return Hash(crypto.SHA256.New(), data) }
func Hash(h hash.Hash, data []byte) []byte { h.Write(data); return h.Sum(nil) }
func NewID() string                        { return shortuuid.New() }
