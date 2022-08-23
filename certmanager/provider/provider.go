package provider

import (
	"context"
	"crypto/x509"
	"time"

	"scas/client/common/x509types"
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
	CommonName                                string   `validate:"required"`
	Hosts                                     []string // DNSNames, IPAddress, Email
	Country, Organization, OrganizationalUnit string
	Locality, Province                        string
	StreetAddress, PostalCode                 string
	SerialNumber                              string
	KeyAlgorithm                              x509types.SignatureAlgorithm `validate:"required"`
	IsCA                                      bool
	KeyUsage                                  x509.KeyUsage
	ExtKeyUsage                               []x509.ExtKeyUsage
	CRL                                       []string
	NotAfter                                  time.Time `validate:"required"`
	NotBefore                                 time.Time `validate:"required"`
}
