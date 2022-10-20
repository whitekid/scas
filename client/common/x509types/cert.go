package x509types

import (
	"crypto/x509"
)

const (
	SignatureAlgorithmRootCA = x509.SHA512WithRSA
	SignatureAlgorithmSubCA  = x509.SHA256WithRSA
	SignatureAlgorithmServer = x509.SHA256WithRSA
)

const (
	KeyUsageRootCA = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	KeyUsageSubCA  = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	KeyUsageServer = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	KeyUsageClient = x509.KeyUsageDigitalSignature
)

var (
	ExtKeyUsageRootCA = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	ExtKeyUsageSubCA  = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	ExtKeyUsageServer = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
)
