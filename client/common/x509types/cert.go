package x509types

import (
	"crypto/x509"
	"encoding/json"
)

const (
	RootCASignatureAlgorithm = x509.SHA512WithRSA
	SubCASignatureAlgorithm  = x509.SHA256WithRSA
	ServerSignatureAlgorithm = x509.SHA256WithRSA
)

const (
	RootCAKeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	SubCAKeyUsage  = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	ServerKeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	ClientKeyUsage = x509.KeyUsageDigitalSignature
)

var (
	RootCAExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	SubCAExtKeyUsage  = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	ServerExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
)

type SignatureAlgorithm int

const (
	KeyUnknown SignatureAlgorithm = iota
	ECDSA_P256                    // generally for leaf
	ECDSA_P384                    // generally ca
	ECDSA_P512
	RSA_2048
	RSA_3072
	RSA_4096
)

var (
	algorithmToStr                    = map[SignatureAlgorithm]string{}
	strToAlgo                         = map[string]SignatureAlgorithm{}
	algoToStr                         = map[SignatureAlgorithm]string{}
	algorithmToKeySize                = map[SignatureAlgorithm]int{}
	algorithmToX509SignatureAlgorithm = map[SignatureAlgorithm]x509.SignatureAlgorithm{}
	x509SignatureAlgorithmToAlgorithm = map[x509.SignatureAlgorithm]SignatureAlgorithm{}
)

func init() {
	for algo, detail := range map[SignatureAlgorithm]struct {
		name               string
		algorithm          string
		size               int
		signatureAlgorithm x509.SignatureAlgorithm
	}{
		ECDSA_P256: {name: "ecdsa256", algorithm: "ecdsa", size: 256, signatureAlgorithm: x509.ECDSAWithSHA256},
		ECDSA_P384: {name: "ecdsa384", algorithm: "ecdsa", size: 384, signatureAlgorithm: x509.ECDSAWithSHA384},
		ECDSA_P512: {name: "ecdsa512", algorithm: "ecdsa", size: 521, signatureAlgorithm: x509.ECDSAWithSHA512},
		RSA_2048:   {name: "rsa2048", algorithm: "rsa", size: 2048, signatureAlgorithm: x509.SHA256WithRSA},
		RSA_3072:   {name: "rsa3072", algorithm: "rsa", size: 3072, signatureAlgorithm: x509.SHA384WithRSAPSS},
		RSA_4096:   {name: "rsa4096", algorithm: "rsa", size: 4096, signatureAlgorithm: x509.SHA512WithRSA},
	} {
		algorithmToStr[algo] = detail.name
		strToAlgo[detail.name] = algo
		algoToStr[algo] = detail.algorithm
		algorithmToKeySize[algo] = detail.size
		algorithmToX509SignatureAlgorithm[algo] = detail.signatureAlgorithm
		x509SignatureAlgorithmToAlgorithm[detail.signatureAlgorithm] = algo
	}
}

func (k SignatureAlgorithm) String() string       { return algorithmToStr[k] }
func (k *SignatureAlgorithm) FromString(s string) { *k = strToAlgo[s] }
func (k *SignatureAlgorithm) ToX509SignatureAlgorithm() x509.SignatureAlgorithm {
	return algorithmToX509SignatureAlgorithm[*k]
}
func X509SignatureAlgorithmToKeyAlgorithm(algo x509.SignatureAlgorithm) SignatureAlgorithm {
	return x509SignatureAlgorithmToAlgorithm[algo]
}

func (k *SignatureAlgorithm) MarshalJSON() ([]byte, error) { return json.Marshal(k.String()) }
func (k *SignatureAlgorithm) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	k.FromString(s)
	return nil
}

func (k SignatureAlgorithm) Algorithm() string { return algoToStr[k] }
func (k SignatureAlgorithm) Size() int         { return algorithmToKeySize[k] }
