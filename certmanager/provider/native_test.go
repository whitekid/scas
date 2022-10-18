package provider

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"scas/pkg/helper"
	"scas/pkg/helper/x509x"
)

func Test_nativeImpl_CreateCertificate(t *testing.T) {
	type args struct {
		req       *CreateRequest
		parent    *x509.Certificate
		signerKey x509x.PrivateKey
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		{`valid self-signed certificate`, args{&CreateRequest{
			CommonName:   "example.127.0.0.1.sslip.io",
			Hosts:        []string{"example.127.0.0.1.sslip.io"},
			KeyAlgorithm: x509.ECDSAWithSHA256,
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
			gotCert, keyPEM, err := na.CreateCertificate(ctx, tt.args.req, tt.args.parent, tt.args.signerKey)
			require.Truef(t, (err != nil) == tt.wantErr, `CreateCertificate() failed: error = %+v, wantErr = %v`, err, tt.wantErr)
			if tt.wantErr {
				return
			}

			cert, err := x509x.ParseCertificate(gotCert)
			require.NoError(t, err)

			key, err := x509x.ParsePrivateKey(keyPEM)
			require.NoError(t, err)

			require.Equal(t, tt.args.req.KeyAlgorithm, x509x.PrivateKeyAlgorithm(key))
			require.Equal(t, tt.args.req.CommonName, cert.Subject.CommonName)
			require.Equal(t, tt.args.req.CommonName, cert.Issuer.CommonName) // self signd
			require.Equal(t, tt.args.req.NotAfter, cert.NotAfter)
			require.Equal(t, tt.args.req.NotBefore, cert.NotBefore)

			require.NoError(t, cert.CheckSignatureFrom(cert))
		})
	}
}

func Test_nativeImpl_CreateCertificateAlgithms(t *testing.T) {
	type args struct {
		isCA               bool
		keyAlgorithm       x509.SignatureAlgorithm
		signatureAlgorithm x509.SignatureAlgorithm
	}
	tests := [...]struct {
		name    string
		args    args
		wantErr bool
	}{
		// IsCA=false, 지원하는 key algorithm
		{`unknown algorithm`, args{false, x509.MD2WithRSA, x509.UnknownSignatureAlgorithm}, true},
		{`unknown algorithm`, args{false, x509.MD5WithRSA, x509.UnknownSignatureAlgorithm}, true},
		{`valid algorithm`, args{false, x509.SHA256WithRSA, x509.UnknownSignatureAlgorithm}, false},
		{`valid algorithm`, args{false, x509.SHA384WithRSA, x509.UnknownSignatureAlgorithm}, false},
		{`valid algorithm`, args{false, x509.SHA512WithRSA, x509.UnknownSignatureAlgorithm}, false},
		{`unknown algorithm`, args{false, x509.DSAWithSHA1, x509.UnknownSignatureAlgorithm}, true},
		{`unknown algorithm`, args{false, x509.DSAWithSHA256, x509.UnknownSignatureAlgorithm}, true},
		{`unknown algorithm`, args{false, x509.ECDSAWithSHA1, x509.UnknownSignatureAlgorithm}, true},
		{`valid algorithm`, args{false, x509.ECDSAWithSHA256, x509.UnknownSignatureAlgorithm}, false},
		{`valid algorithm`, args{false, x509.ECDSAWithSHA384, x509.UnknownSignatureAlgorithm}, false},
		{`valid algorithm`, args{false, x509.ECDSAWithSHA512, x509.UnknownSignatureAlgorithm}, false},
		{`unknown algorithm`, args{false, x509.SHA256WithRSAPSS, x509.UnknownSignatureAlgorithm}, true},
		{`unknown algorithm`, args{false, x509.SHA384WithRSAPSS, x509.UnknownSignatureAlgorithm}, true},
		{`unknown algorithm`, args{false, x509.SHA512WithRSAPSS, x509.UnknownSignatureAlgorithm}, true},
		{`valid algorithm`, args{false, x509.PureEd25519, x509.UnknownSignatureAlgorithm}, false},

		{`algorithm mismatch`, args{false, x509.SHA256WithRSA, x509.ECDSAWithSHA256}, true},
		{`algorithm mismatch`, args{false, x509.ECDSAWithSHA256, x509.SHA256WithRSA}, true},
		{`algorithm mismatch`, args{false, x509.PureEd25519, x509.SHA256WithRSA}, true},

		{`invalid valid signature algorithm`, args{false, x509.SHA256WithRSA, x509.MD2WithRSA}, true},

		{`valid`, args{false, x509.SHA256WithRSA, x509.SHA256WithRSA}, false},
		{`valid`, args{false, x509.SHA384WithRSA, x509.SHA384WithRSA}, false},
		{`valid`, args{false, x509.SHA512WithRSA, x509.SHA512WithRSA}, false},
		{`valid`, args{false, x509.ECDSAWithSHA256, x509.ECDSAWithSHA256}, false},
		{`valid`, args{false, x509.ECDSAWithSHA384, x509.ECDSAWithSHA384}, false},
		{`valid`, args{false, x509.ECDSAWithSHA512, x509.ECDSAWithSHA512}, false},
		{`valid`, args{false, x509.PureEd25519, x509.PureEd25519}, false},

		// ISCA=true
		{`unknown algorithm`, args{true, x509.MD2WithRSA, x509.UnknownSignatureAlgorithm}, true},
		{`unknown algorithm`, args{true, x509.MD5WithRSA, x509.UnknownSignatureAlgorithm}, true},
		{`unknown algorithm`, args{true, x509.SHA1WithRSA, x509.UnknownSignatureAlgorithm}, true},
		{`valid`, args{true, x509.SHA256WithRSA, x509.UnknownSignatureAlgorithm}, false},
		{`valid`, args{true, x509.SHA256WithRSA, x509.UnknownSignatureAlgorithm}, false},
		{`valid`, args{true, x509.SHA384WithRSA, x509.UnknownSignatureAlgorithm}, false},
		{`valid`, args{true, x509.SHA512WithRSA, x509.UnknownSignatureAlgorithm}, false},
		{`valid`, args{true, x509.ECDSAWithSHA256, x509.UnknownSignatureAlgorithm}, false},
		{`valid`, args{true, x509.ECDSAWithSHA384, x509.UnknownSignatureAlgorithm}, false},
		{`valid`, args{true, x509.ECDSAWithSHA512, x509.UnknownSignatureAlgorithm}, false},
		{`valid`, args{true, x509.PureEd25519, x509.UnknownSignatureAlgorithm}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			na := Native().(*nativeImpl)
			_, _, err := na.CreateCertificate(ctx, &CreateRequest{
				CommonName:         "charlie.127.0.0.1.sslip.io",
				Hosts:              []string{"charlie.127.0.0.1.sslip.io"},
				KeyAlgorithm:       tt.args.keyAlgorithm,
				SignatureAlgorithm: tt.args.signatureAlgorithm,
				IsCA:               tt.args.isCA,
				NotAfter:           helper.AfterNow(1, 0, 0),
				NotBefore:          helper.AfterNow(0, -1, 0),
			}, nil, nil)
			require.Truef(t, (err != nil) == tt.wantErr, `CreateCertificate() failed: error = %+v, wantErr = %v, algo=%s, sigAlgo=%s`, err, tt.wantErr, tt.args.keyAlgorithm.String(), tt.args.signatureAlgorithm.String())
			if tt.wantErr == true {
				return
			}

			require.NoError(t, x509x.ValidCertificateAlgorithm(tt.args.isCA, tt.args.keyAlgorithm, tt.args.signatureAlgorithm))
		})
	}
}
