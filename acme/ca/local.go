package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"net"
	"net/mail"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/fx"

	"scas/pkg/helper"
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
	if err := helper.ValidateStruct(in); err != nil {
		return nil, nil, nil, err
	}

	privKey, err := x509x.GenerateKey(in.KeyAlgorithm)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "fail to create certificate")
	}
	parentPrivKey := privKey

	template := &x509.Certificate{
		SignatureAlgorithm:    fx.Ternary(in.SignatureAlgorithm == x509.UnknownSignatureAlgorithm, in.KeyAlgorithm, in.SignatureAlgorithm),
		SerialNumber:          fx.Ternary(in.SerialNumber == nil, x509x.RandomSerial(), in.SerialNumber),
		Subject:               in.Subject,
		Issuer:                in.Issuer,
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

	for _, s := range in.Hosts {
		if ip := net.ParseIP(s); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if m, err := mail.ParseAddress(s); err == nil {
			template.EmailAddresses = append(template.EmailAddresses, m.Address)
		} else {
			template.DNSNames = append(template.DNSNames, s)
		}
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
