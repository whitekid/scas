package provider

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/mail"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp"
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

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: req.CommonName,
		},
		IsCA:                  req.IsCA,
		BasicConstraintsValid: req.IsCA,
		NotAfter:              req.NotAfter,
		NotBefore:             req.NotBefore,
		KeyUsage:              req.KeyUsage,
		ExtKeyUsage:           req.ExtKeyUsage,
		CRLDistributionPoints: req.CRL,
	}

	for _, host := range req.Hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(host); err == nil {
			template.EmailAddresses = append(template.EmailAddresses, email.Address)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	if !template.IsCA && len(template.DNSNames) == 0 {
		return nil, nil, errors.Wrap(err, "DNS name required")
	}

	goxp.IfThen(req.Country != "", func() { template.Subject.Country = []string{req.Country} })
	goxp.IfThen(req.Organization != "", func() { template.Subject.Organization = []string{req.Organization} })
	goxp.IfThen(req.OrganizationalUnit != "", func() { template.Subject.OrganizationalUnit = []string{req.OrganizationalUnit} })
	goxp.IfThen(req.Locality != "", func() { template.Subject.Locality = []string{req.Locality} })
	goxp.IfThen(req.Province != "", func() { template.Subject.Province = []string{req.Province} })
	goxp.IfThen(req.StreetAddress != "", func() { template.Subject.StreetAddress = []string{req.StreetAddress} })
	goxp.IfThen(req.PostalCode != "", func() { template.Subject.PostalCode = []string{req.PostalCode} })

	if req.SerialNumber == "" {
		template.SerialNumber = x509x.RandSerial()
	} else {
		serial, ok := template.SerialNumber.SetString(req.SerialNumber, 10)
		if !ok {
			return nil, nil, errors.Wrap(err, "fail to create certificate")
		}
		template.SerialNumber = serial
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
