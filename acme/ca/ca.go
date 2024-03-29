package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"time"
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
	KeyAlgorithm       x509.SignatureAlgorithm `validate:"required"`
	SignatureAlgorithm x509.SignatureAlgorithm
	Subject            pkix.Name
	Issuer             pkix.Name
	Hosts              []string
	URIs               []*url.URL
	NotBefore          time.Time
	NotAfter           time.Time
	KeyUsage           x509.KeyUsage
	ExtKeyUsage        []x509.ExtKeyUsage
	Extensions         []pkix.Extension
	ExtraExtensions    []pkix.Extension
}
