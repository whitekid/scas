package x509x

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sort"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"
)

const (
	CertificatePEMBlockType              = "CERTIFICATE"
	CrlPEMBlockType                      = "X509 CRL"
	CsrPEMBlockType                      = "CERTIFICATE REQUEST"
	OldCsrPEMBlockType                   = "NEW CERTIFICATE REQUEST"
	RsaPrivateKeyPEMBlockType            = "RSA PRIVATE KEY"
	EcdsaPrivateKeyPEMBlockType          = "EC PRIVATE KEY"
	Pkcs8PrivateKeyPEMBlockType          = "PRIVATE KEY"
	EncryptedPKCS8PrivateKeyPEMBLockType = "ENCRYPTED PRIVATE KEY"

	pemPrefix = "-----BEGIN "
)

var (
	pemPrefixCertificate     = []byte(pemPrefix + CertificatePEMBlockType)
	pemPrefixCSR             = []byte(pemPrefix + CsrPEMBlockType)
	pemPrefixRsaPrivateKey   = []byte(pemPrefix + RsaPrivateKeyPEMBlockType)
	pemPrefixEcdsaPrivateKey = []byte(pemPrefix + EcdsaPrivateKeyPEMBlockType)
	pemPrefixPkcs8PrivateKey = []byte(pemPrefix + Pkcs8PrivateKeyPEMBlockType)
)

var randReader = rand.Reader

// ParseCertificate parse x509 certificate PEM block or DER bytes
func ParseCertificate(certBytes []byte) (*x509.Certificate, error) {
	if bytes.HasPrefix(certBytes, pemPrefixCertificate) {
		p, _ := pem.Decode(certBytes)
		if p == nil {
			return nil, errors.New("invalid PEM")
		}

		certBytes = p.Bytes
	}

	return x509.ParseCertificate(certBytes)
}

func ParseCertificateChain(derBytes []byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)
	for {
		p, rest := pem.Decode(derBytes)
		if p == nil {
			return certs, nil
		}

		cert, err := ParseCertificate(p.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "certificate parse failed")
		}
		certs = append(certs, cert)
		derBytes = rest
	}
}

// ParseCSR parse x509 CSR PEM block
func ParseCSR(csrBytes []byte) (*x509.CertificateRequest, error) {
	if bytes.HasPrefix(csrBytes, pemPrefixCSR) {
		p, _ := pem.Decode(csrBytes)
		if p == nil {
			return nil, errors.New("invalid PEM")
		}

		csrBytes = p.Bytes
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

// PublicKey  PrivateKey and Signer interfaces
// crypto.PrivateKey의 설명을 보면 함수가 다 있다고 함.
type PrivateKey interface {
	crypto.PrivateKey
	crypto.Signer
}

type PublicKey interface {
	Equal(x crypto.PublicKey) bool
}

// GenerateKey generate private and public key pair
func GenerateKey(algorithm x509.SignatureAlgorithm) (privateKey PrivateKey, err error) {
	switch algorithm {
	case x509.ECDSAWithSHA256:
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), randReader)
	case x509.ECDSAWithSHA384:
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), randReader)
	case x509.ECDSAWithSHA512:
		privateKey, err = ecdsa.GenerateKey(elliptic.P521(), randReader)
	case x509.PureEd25519:
		_, privateKey, err = ed25519.GenerateKey(randReader)
	case x509.SHA256WithRSA:
		privateKey, err = rsa.GenerateKey(randReader, 256*8)
	case x509.SHA384WithRSA:
		privateKey, err = rsa.GenerateKey(randReader, 384*8)
	case x509.SHA512WithRSA:
		privateKey, err = rsa.GenerateKey(randReader, 512*8)
	default:
		return nil, errors.Errorf("unknown algorithm: %s", algorithm)
	}

	if err != nil {
		return nil, err
	}

	return
}

// ParsePrivateKey parse pem formatted priate key
func ParsePrivateKey(keyPemBytes []byte) (PrivateKey, error) {
	p, _ := pem.Decode(keyPemBytes)
	if p == nil {
		return nil, errors.New("invalid PEM")
	}

	var key PrivateKey
	var err error
	switch {
	case bytes.HasPrefix(keyPemBytes, pemPrefixRsaPrivateKey):
		key, err = x509.ParsePKCS1PrivateKey(p.Bytes)

	case bytes.HasPrefix(keyPemBytes, pemPrefixEcdsaPrivateKey):
		key, err = x509.ParseECPrivateKey(p.Bytes)

	default:
		return nil, errors.New("Unknown pem type")
	}

	if err != nil {
		return nil, errors.Wrap(err, "fail to parse private key")
	}
	return key, nil
}

// CreateCertificateRequest create CSR and return PEM
// privateKey: signer private key
func CreateCertificateRequest(template *x509.CertificateRequest) (csr []byte, pemBytes []byte, err error) {
	privKey, err := GenerateKey(template.SignatureAlgorithm)
	if err != nil {
		return nil, nil, err
	}

	derBytes, err := x509.CreateCertificateRequest(randReader, template, privKey)
	if err != nil {
		return nil, nil, err
	}

	block := &pem.Block{
		Type:    CsrPEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	return derBytes, pem.EncodeToMemory(block), nil
}

func EncodeCertificateToPEM(derBytes []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    CertificatePEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	})
}

func EncodePrivateKeyToPEM(privateKey PrivateKey) ([]byte, error) {
	var pemType string
	var keyBytes []byte

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		pemType = RsaPrivateKeyPEMBlockType
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	case *ecdsa.PrivateKey:
		pemType = EcdsaPrivateKeyPEMBlockType
		derBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, errors.Wrap(err, "fail to encode private key")
		}
		keyBytes = derBytes
	case ed25519.PrivateKey:
		pemType = EcdsaPrivateKeyPEMBlockType
		derBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, errors.Wrap(err, "fail to encode private key")
		}
		keyBytes = derBytes
	default:
		return nil, errors.Errorf("unsupported private key: %T", privateKey)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: keyBytes,
	}), nil
}

var (
	keyUsageToStr = map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "Digital Signature",
		x509.KeyUsageContentCommitment: "Non Repudiation",
		x509.KeyUsageKeyEncipherment:   "Key Encipherment",
		x509.KeyUsageDataEncipherment:  "Data Encipherment",
		x509.KeyUsageKeyAgreement:      "Key Agreement",
		x509.KeyUsageCertSign:          "Certificate Sign",
		x509.KeyUsageCRLSign:           "CRL Sign",
		x509.KeyUsageEncipherOnly:      "Encipher Only",
		x509.KeyUsageDecipherOnly:      "Decipher Only",
	}
	extKeyUsageToStr = map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "UsageA ny",
		x509.ExtKeyUsageServerAuth:                     "TLS Web Server Authentication",
		x509.ExtKeyUsageClientAuth:                     "TLS Web Client Authentication",
		x509.ExtKeyUsageCodeSigning:                    "Code Signing",
		x509.ExtKeyUsageEmailProtection:                "Email Protection",
		x509.ExtKeyUsageIPSECEndSystem:                 "IPSEC End System",
		x509.ExtKeyUsageIPSECTunnel:                    "IPSEC Tunnel",
		x509.ExtKeyUsageIPSECUser:                      "IPSEC User",
		x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
	}

	keyUsages    []x509.KeyUsage
	extKeyUsages []x509.ExtKeyUsage
)

func init() {
	keyUsages = fx.Keys(keyUsageToStr)
	sort.Slice(keyUsages, func(i, j int) bool { return int(keyUsages[i]) < int(keyUsages[j]) })

	extKeyUsages = fx.Keys(extKeyUsageToStr)
	sort.Slice(extKeyUsages, func(i, j int) bool { return int(extKeyUsages[i]) < int(extKeyUsages[j]) })
}

// KeyUsageToStr
func KeyUsageToStr(keyUsage x509.KeyUsage) (usages []string) {
	for _, u := range keyUsages {
		if keyUsage&u > 0 {
			usages = append(usages, keyUsageToStr[u])
		}
	}
	return usages
}

// ExtKeyUsageToStr
func ExtKeyUsageToStr(keyUsage []x509.ExtKeyUsage) (usages []string) {
	for _, u := range keyUsage {
		usages = append(usages, extKeyUsageToStr[u])
	}
	return usages
}

func RandomSerial() *big.Int {
	s, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return s
}

func VerifySignature(pub PublicKey, hash []byte, signature []byte) bool {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(p, hash, signature)
	default:
		log.Fatalf("unsupported public key: %T", pub)
		return false
	}
}
