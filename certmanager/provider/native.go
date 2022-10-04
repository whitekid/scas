package provider

import (
	"context"
	"crypto/rand"
	"crypto/x509"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/log"

	"scas/pkg/helper/x509x"
)

func Native() Interface {
	return &nativeImpl{}
}

type nativeImpl struct {
}

var _ Interface = (*nativeImpl)(nil)

// CreateCertificate create certificate
func (na *nativeImpl) CreateCertificate(ctx context.Context, req *CreateRequest, signer *x509.Certificate, signerPrivateKey x509x.PrivateKey) ([]byte, []byte, error) {
	log.Debugf("CreateCertificate(): req=%v", req)

	privateKey, err := x509x.GenerateKey(req.KeyAlgorithm.ToX509SignatureAlgorithm())
	if err != nil {
		return nil, nil, errors.Wrap(err, "fail to create certificate")
	}

	template, err := req.Template()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "fail to create template")
	}

	if signer == nil {
		signer = template
		signerPrivateKey = privateKey
	}

	certDerBytes, err := x509.CreateCertificate(rand.Reader, template, signer, privateKey.Public(), signerPrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "fail to create certificate")
	}

	privatePEMBytes, err := x509x.EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "fail to create certificate")
	}

	return x509x.EncodeCertificateToPEM(certDerBytes), privatePEMBytes, nil
}
