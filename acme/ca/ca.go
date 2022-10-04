package ca

import (
	"crypto/rand"
	"crypto/x509"

	"github.com/pkg/errors"

	"scas/certmanager"
	"scas/pkg/helper/x509x"
)

type Local struct {
}

func New() *Local {
	return &Local{}
}

// CreateCertificate create certificate and returns DER format
// TODO 일반화면 x509.Certificate로 부터 만들어야 하는데.... 흠.. 좀더 고민이 필요하네..
func (loc *Local) CreateCertificate(req *certmanager.CreateRequest, parent *x509.Certificate, publicKey any, parentPrivateKey any) ([]byte, error) {
	template, err := req.Template()
	if err != nil {
		return nil, errors.Wrap(err, "fail to create certificate")
	}

	if parent == nil {
		parent = template
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentPrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "fail to create certificate")
	}

	return x509x.EncodeCertificateToPEM(cert), nil
}
