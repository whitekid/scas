package testutils

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"scas/pkg/helper"
	"scas/pkg/helper/x509x"
)

func TestClientCRL(t *testing.T) {
	// generate test CRL
	type args struct {
		crlBytes       []byte
		caCertBytes    []byte
		certBytes      []byte
		chainCertBytes []byte
	}
	tests := [...]struct {
		name             string
		arg              args
		wantCrlErr       bool
		wantSignatureErr bool
		wantBefore       bool
		wantErr          bool
	}{
		{`valid: digicert`, args{
			helper.MustReadFile("fixtures/DigiCertTLSHybridECCSHA3842020CA1-1.crl"), // DigiCert CRL
			helper.MustReadFile("fixtures/digicert-ca1.pem"),                        // DigiCert CA
			helper.MustReadFile("fixtures/github-com.pem"),                          // github.com has digcert certficiate
			helper.MustReadFile("fixtures/github-com-chain.pem"),                    // github.com certificatie chain
		}, false, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crl, err := x509.ParseRevocationList(tt.arg.crlBytes)
			require.Truef(t, (err != nil) == tt.wantCrlErr, `ParseRevocationList() failed`, `error = %v, wantCrlErr = %v`, err, tt.wantCrlErr)

			caCert, err := x509x.ParseCertificate(tt.arg.caCertBytes)
			require.NoError(t, err)

			err = crl.CheckSignatureFrom(caCert)
			require.Truef(t, (err != nil) == tt.wantSignatureErr, "CheckSignatureFrom() failed", `error = %v, wantSignatureErr = %v`, err, tt.wantSignatureErr)
			require.Equal(t, tt.wantBefore, crl.NextUpdate.After(time.Now()))

			tc := &tls.Config{
				VerifyPeerCertificate: NewVerifier().Verify,
			}

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tc,
				},
			}
			_, err = client.Get("https://github.com")
			require.Truef(t, (err != nil) == tt.wantErr, `Get() failed: error = %v, wantErr = %v`, err, tt.wantErr)
		})
	}
}

type CRLVerifier interface {
	Verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

func NewVerifier() CRLVerifier {
	return &crlVerifier{
		crls: map[string]*x509.RevocationList{},
	}
}

type crlVerifier struct {
	crls map[string]*x509.RevocationList // cached crl items: distEndpoint -> CRL
}

var _ CRLVerifier = (*crlVerifier)(nil)

func (v *crlVerifier) Verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	for _, chain := range verifiedChains {
		for i := 0; i < len(chain)-1; i++ {
			cert := chain[i]
			issuer := chain[i+1]

			for _, distPoint := range cert.CRLDistributionPoints {
				crl, err := v.getCRL(distPoint, issuer)
				if err != nil {
					return errors.Wrap(err, "crl verify failed")
				}

				if err := v.checkCertWithCRL(cert, crl); err != nil {
					return errors.Wrap(err, "crl verify failed")
				}
			}
		}
	}

	return nil
}

func (v *crlVerifier) getCRL(url string, issuer *x509.Certificate) (*x509.RevocationList, error) {
	crl, ok := v.crls[url]
	if ok {
		return crl, nil
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.Wrap(err, "crl get failed")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrapf(err, "crl get failed with status %d", resp.StatusCode)

	}

	defer resp.Body.Close()
	crlByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "crl get failed")
	}

	crl, err = x509.ParseRevocationList(crlByte)
	if err != nil {
		return nil, errors.Wrap(err, "crl parse failed")
	}

	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return nil, errors.Wrap(err, "crl signature check failed")
	}

	if crl.NextUpdate.Before(time.Now()) {
		return nil, errors.Wrap(err, "crl %s was outd")
	}

	v.crls[url] = crl

	return crl, nil
}

var ErrCertWasRevoked = errors.New("certificate was revoked")

func (v *crlVerifier) checkCertWithCRL(cert *x509.Certificate, crl *x509.RevocationList) error {
	for _, revoked := range crl.RevokedCertificates {
		if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return ErrCertWasRevoked
		}
	}

	return nil
}
