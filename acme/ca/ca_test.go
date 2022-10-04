package ca

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"scas/certmanager/provider"
	"scas/client/common"
	"scas/client/common/x509types"
	"scas/pkg/helper/x509x"
)

func TestLocal_CreateCertificate(t *testing.T) {
	privateKey, err := x509x.GenerateKey(x509.ECDSAWithSHA256)
	require.NoError(t, err)

	type args struct {
		csr              *provider.CreateRequest
		parent           *x509.Certificate
		publicKey        any
		parentPrivateKey any
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid", args{&provider.CreateRequest{
			CommonName:   "test.charlie.127.0.0.1.sslip.io",
			Hosts:        []string{"test.charlie.127.0.0.1.sslip.io"},
			NotAfter:     common.TimestampNow().AddDate(1, 0, 0).Time,
			NotBefore:    common.TimestampNow().AddDate(0, 1, 0).Time,
			KeyAlgorithm: x509types.ECDSA_P256,
		}, nil, privateKey.Public(), privateKey}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loc := &Local{}
			cert, err := loc.CreateCertificate(tt.args.csr, tt.args.parent, tt.args.publicKey, tt.args.parentPrivateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("Local.CreateCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got, err := x509x.ParseCertificate(cert)
			require.NoError(t, err)
			require.Equal(t, got.Subject.CommonName, tt.args.csr.CommonName)
		})
	}
}
