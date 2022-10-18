package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/whitekid/goxp/fx"

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
		{"key algo", args{&CreateRequest{
			Subject:            pkix.Name{CommonName: "hello.example.com"},
			KeyAlgorithm:       x509.ECDSAWithSHA256,
			SignatureAlgorithm: x509.ECDSAWithSHA512,
		}}, false},
		{"valid", args{&CreateRequest{
			Subject:      pkix.Name{CommonName: "hello.example.com"},
			KeyAlgorithm: x509.SHA512WithRSA,
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
			if tt.args.req.SerialNumber != nil {
				require.Equal(t, tt.args.req.SerialNumber, cert.SerialNumber)
			}
			require.Equal(t, tt.args.req.Subject.CommonName, cert.Subject.CommonName)

			sigAlgo := fx.Ternary(tt.args.req.SignatureAlgorithm == x509.UnknownSignatureAlgorithm, tt.args.req.KeyAlgorithm, tt.args.req.SignatureAlgorithm)
			require.Equal(t, sigAlgo.String(), cert.SignatureAlgorithm.String())

			priv, err := x509x.ParsePrivateKey(key)
			require.NoError(t, err)
			require.Equal(t, tt.args.req.KeyAlgorithm.String(), x509x.PrivateKeyAlgorithm(priv).String())

			require.Empty(t, chain)
		})
	}
}
