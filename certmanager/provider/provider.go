package provider

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/mail"
	"time"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/fx"

	"scas/client/common/x509types"
	"scas/pkg/helper"
	"scas/pkg/helper/x509x"
)

// Intrface certificate provider
type Interface interface {
	// CreateCertificate
	// signer: if nil, generate CA certficiate for root CA, else generate subordinate CA certificate
	// returns DER encoded certificated and private key
	CreateCertificate(ctx context.Context, req *CreateRequest, signer *x509.Certificate, signerPrivateKey x509x.PrivateKey) (certPEMBytes []byte, privateKeyPEMBytes []byte, err error)
}

type CreateRequest struct {
	SerialNumber                              *big.Int
	CommonName                                string   `validate:"required"`
	Hosts                                     []string // DNSNames, IPAddress, Email
	Country, Organization, OrganizationalUnit string
	Locality, Province                        string
	StreetAddress, PostalCode                 string
	KeyAlgorithm                              x509types.SignatureAlgorithm `validate:"required"`
	SignatureAlgorithm                        x509types.SignatureAlgorithm
	IsCA                                      bool
	KeyUsage                                  x509.KeyUsage
	ExtKeyUsage                               []x509.ExtKeyUsage
	CRL                                       []string  // Certificate Revocation List
	NotAfter                                  time.Time `validate:"required"`
	NotBefore                                 time.Time `validate:"required"`
}

// Template convert to x509x certificate template
func (req *CreateRequest) Template() (*x509.Certificate, error) {
	if err := helper.ValidateStruct(req); err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SignatureAlgorithm: fx.Ternary(req.SignatureAlgorithm == x509types.KeyUnknown, req.KeyAlgorithm.ToX509SignatureAlgorithm(), req.KeyAlgorithm.ToX509SignatureAlgorithm()),
		SerialNumber:       fx.Ternary(req.SerialNumber == nil, x509x.RandomSerial(), req.SerialNumber),
		Subject: pkix.Name{
			CommonName:         req.CommonName,
			Country:            fx.Ternary(req.Country != "", []string{req.Country}, nil),
			Organization:       fx.Ternary(req.Organization != "", []string{req.Organization}, nil),
			OrganizationalUnit: fx.Ternary(req.OrganizationalUnit != "", []string{req.OrganizationalUnit}, nil),
			Locality:           fx.Ternary(req.Locality != "", []string{req.Locality}, nil),
			Province:           fx.Ternary(req.Province != "", []string{req.Province}, nil),
			StreetAddress:      fx.Ternary(req.StreetAddress != "", []string{req.StreetAddress}, nil),
			PostalCode:         fx.Ternary(req.PostalCode != "", []string{req.PostalCode}, nil),
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
		return nil, errors.Errorf("DNS name required")
	}

	return template, nil
}
