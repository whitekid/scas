package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"time"

	"scas/client/common/x509types"
)

type Interface interface {
	// create certificate and returns as PEM format
	// if certificate has chain, it returns cert, key, certificate chain
	//
	// KeyAlgorithm & SignatureAlgoritham should have same algorithm
	CreateCertificate(ctx context.Context, in *CreateRequest) ([]byte, []byte, []byte, error)
}

// CreateRequest certificate create request
type CreateRequest struct {
	SerialNumber       *big.Int
	KeyAlgorithm       x509types.SignatureAlgorithm `validate:"required"`
	SignatureAlgorithm x509types.SignatureAlgorithm
	Subject            pkix.Name
	Issuer             pkix.Name
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []net.IP
	URIs               []*url.URL
	NotBefore          time.Time
	NotAfter           time.Time
	KeyUsage           x509.KeyUsage
	ExtKeyUsage        []x509.ExtKeyUsage
	Extensions         []pkix.Extension
	ExtraExtensions    []pkix.Extension
}
