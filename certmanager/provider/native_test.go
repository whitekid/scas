package provider

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"scas/client/common/x509types"
	"scas/pkg/helper"
	"scas/pkg/helper/x509x"
)

func Test_nativeImpl_CreateCertificate(t *testing.T) {
	type args struct {
		req       *CreateRequest
		parent    *x509.Certificate
		parentKey x509x.PrivateKey
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`valid self-signed ca certificate`, args{&CreateRequest{
			CommonName:   "example.com",
			KeyAlgorithm: x509types.ECDSA_P256,
			IsCA:         true,
			NotAfter:     helper.AfterNow(1, 0, 0),
			NotBefore:    helper.AfterNow(0, -1, 0),
		}, nil, nil}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			na := Native().(*nativeImpl)
			gotCert, _, err := na.CreateCertificate(ctx, tt.args.req, tt.args.parent, tt.args.parentKey)
			require.Truef(t, (err != nil) == tt.wantErr, `createCertificateAuthority() failed: error = %+v, wantErr = %v`, err, tt.wantErr)

			cert, err := x509x.ParseCertificate(gotCert)
			require.NoError(t, err)

			require.Equal(t, tt.args.req.KeyAlgorithm.ToX509SignatureAlgorithm(), cert.SignatureAlgorithm)
			require.Equal(t, tt.args.req.CommonName, cert.Subject.CommonName)
			require.Equal(t, tt.args.req.CommonName, cert.Issuer.CommonName) // self signd
			require.Equal(t, tt.args.req.NotAfter, cert.NotAfter)
			require.Equal(t, tt.args.req.NotBefore, cert.NotBefore)

			require.NoError(t, cert.CheckSignatureFrom(cert))
		})
	}
}
