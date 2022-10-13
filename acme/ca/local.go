package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"

	"github.com/pkg/errors"

	"scas/pkg/helper/x509x"
)

// NewLocal local ca
// local ca는 self signed certificate만 상대함.
func NewLocal() Interface {
	return &localImpl{}
}

type localImpl struct {
}

var _ Interface = (*localImpl)(nil)

func (loc *localImpl) CreateCertificate(ctx context.Context, in *CreateRequest) ([]byte, []byte, []byte, error) {
	privKey, err := x509x.GenerateKey(x509.ECDSAWithSHA256)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "fail to create certificate")
	}
	parentPrivKey := privKey

	template := &x509.Certificate{
		SerialNumber:          in.SerialNumber,
		Subject:               in.Subject,
		Issuer:                in.Issuer,
		DNSNames:              in.DNSNames,
		EmailAddresses:        in.EmailAddresses,
		IPAddresses:           in.IPAddresses,
		URIs:                  in.URIs,
		NotBefore:             in.NotBefore,
		NotAfter:              in.NotAfter,
		KeyUsage:              in.KeyUsage,
		ExtKeyUsage:           in.ExtKeyUsage,
		Extensions:            in.Extensions,
		ExtraExtensions:       in.ExtraExtensions,
		IsCA:                  false,
		BasicConstraintsValid: false,
	}
	parent := template

	certDer, err := x509.CreateCertificate(rand.Reader, template, parent, privKey.Public(), parentPrivKey)
	if err != nil {
		return nil, nil, nil, err
	}

	privKeyPEM, err := x509x.EncodePrivateKeyToPEM(privKey)
	if err != nil {
		return nil, nil, nil, err
	}

	return x509x.EncodeCertificateToPEM(certDer), privKeyPEM, nil, nil
}
