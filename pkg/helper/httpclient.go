package helper

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/log"
)

func NewCRLVerifyTransporter() http.RoundTripper {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			VerifyPeerCertificate: NewCRLVerifier().Verify,
		},
	}
}

type CRLVerifier interface {
	Verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

func NewCRLVerifier() CRLVerifier {
	return &crlVerifier{
		crls: map[string]*x509.RevocationList{},
	}
}

type crlVerifier struct {
	crls  map[string]*x509.RevocationList // cached crl items: distEndpoint -> CRL
	muCrl sync.Mutex
}

var _ CRLVerifier = (*crlVerifier)(nil)

// verifiedChains CRL verifiy를 해야할 인증서들... leaf --> subordany CA -> root CA
// 흠.. CRL이 leaf 인증서에 설정이 되어 있는디...
func (v *crlVerifier) Verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	log.Debugf("rawCerts: %d", len(rawCerts))

	for _, chain := range verifiedChains {
		for _, cert := range chain {
			log.Debugf("CN=%s, CRL=%s", cert.Subject.CommonName, cert.CRLDistributionPoints)
		}

		for i := 0; i < len(chain)-1; i++ {
			cert := chain[i]
			issuer := chain[i+1]

			log.Debugf("verify against to issuer %s", issuer.Subject.CommonName)

			for _, distPoint := range cert.CRLDistributionPoints {
				crl, err := v.getCRL(distPoint, issuer)
				if err != nil {
					return errors.Wrap(err, "crl verify failed")
				}

				if err := CheckCertWithCRL(cert, crl); err != nil {
					return errors.Wrap(err, "crl verify failed")
				}
			}
		}
	}

	return nil
}

var (
	ErrCertWasRevoked = errors.New("certificate was revoked")
	ErrCRLOutdated    = errors.New("CRL was outdated")
)

func (v *crlVerifier) getCRL(url string, issuer *x509.Certificate) (*x509.RevocationList, error) {
	crl, ok := v.crls[url]
	if ok {
		if !crl.NextUpdate.Before(time.Now()) {
			return crl, nil
		}

		log.Infof("CRL outdated, fetch new CRL: %s", crl.Issuer.CommonName)
		v.muCrl.Lock()
		delete(v.crls, url)
		v.muCrl.Unlock()
	}

	log.Debugf("load CRL from: %s", url)
	crlByte, err := ReadFileOrURL(url)
	if err != nil {
		return nil, errors.Wrap(err, "CRL get failed")
	}

	crl, err = x509.ParseRevocationList(crlByte)
	if err != nil {
		return nil, errors.Wrap(err, "CRL parse failed")
	}

	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return nil, errors.Wrap(err, "CRL signature check failed")
	}

	if crl.NextUpdate.Before(time.Now()) {
		return nil, ErrCRLOutdated
	}

	v.muCrl.Lock()
	v.crls[url] = crl
	v.muCrl.Unlock()

	return crl, nil
}

// ReadFileOrURL read http://.. or file://..
func ReadFileOrURL(s string) ([]byte, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "http", "https":
		resp, err := http.Get(u.String())
		if err != nil {
			return nil, errors.Wrapf(err, "url get failed: url=%s", u.String())
		}

		if resp.StatusCode != http.StatusOK {
			return nil, errors.Wrapf(err, "url get failed with status: %s=url, status=%d", u.String(), resp.StatusCode)
		}

		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	case "file":
		return ReadFile(u.Path)
	default:
		return nil, errors.Wrap(err, "unsupported url sch")
	}
}

func CheckCertWithCRL(cert *x509.Certificate, crl *x509.RevocationList) error {
	log.Debugf("check certficate with crl: cn=%s, crl.number=%s", cert.Issuer.CommonName, crl.Number)
	for _, revoked := range crl.RevokedCertificates {
		log.Debugf("cert serial=%s, revoked serial=%s", cert.SerialNumber, revoked.SerialNumber)
		if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			log.Debugf("cert %s was revoked", revoked.SerialNumber)
			return ErrCertWasRevoked
		}
	}

	return nil
}
