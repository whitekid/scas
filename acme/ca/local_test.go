package ca

import (
	"context"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/require"

	"scas/pkg/helper/x509x"
)

func Test_localImpl_CreateCertificate(t *testing.T) {
	type args struct {
		req *CreateRequest
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid", args{&CreateRequest{
			SerialNumber: x509x.RandomSerial(),
			Subject: pkix.Name{
				CommonName: "hello.example.com",
			},
		}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			loc := &localImpl{}
			got, key, chain, err := loc.CreateCertificate(ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("localImpl.CreateSelfSignedCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			cert, err := x509x.ParseCertificate(got)
			require.NoError(t, err)
			require.Equal(t, tt.args.req.SerialNumber, cert.SerialNumber)
			require.Equal(t, tt.args.req.Subject.CommonName, cert.Subject.CommonName)

			priv, err := x509x.ParsePrivateKey(key)
			require.NoError(t, err)
			_ = priv

			require.Empty(t, chain)
		})
	}
}
