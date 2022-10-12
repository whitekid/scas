package helper

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestSHA256Sum(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"valid", args{[]byte(`hello world`)}, `b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hex.EncodeToString(SHA256Sum(tt.args.data)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SHA256Sum() = %v, want %v", got, tt.want)
			}
		})
	}
}
