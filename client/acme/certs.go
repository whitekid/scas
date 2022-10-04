package acme

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"

	"scas/client/common/x509types"

	"github.com/pkg/errors"
)

// Certificate represents certificate services
func (client *ACMEClient) Certificate(endpoint string) *CertService {
	return &CertService{
		client:   client,
		endpoint: endpoint,
	}
}

type CertService struct {
	client   *ACMEClient
	endpoint string
}

// Get get certificate as PEM format
func (svc *CertService) Get(ctx context.Context) ([]byte, error) {
	resp, err := svc.client.sendJOSERequest(ctx, http.MethodPost, svc.endpoint, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to request download certificate")
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to request download certificate")
	}

	return body, nil
}

type CertificateRevoke struct {
	Certificate string `json:"certificate" validate:"required"` // base64 encoded der format
	Reason      int    `json:"reason"`
}

func (svc *CertService) Revoke(ctx context.Context, certPEM []byte, reason x509types.RevokeReason) error {
	p, _ := pem.Decode(certPEM)
	if p == nil {
		return errors.New("invalid PEM format")
	}

	_, err := svc.client.sendJOSERequest(ctx, http.MethodPost, svc.client.directory.RevokeCert,
		&CertificateRevoke{
			Certificate: base64.RawURLEncoding.EncodeToString(p.Bytes),
			Reason:      int(reason),
		})
	if err != nil {
		return err
	}

	return nil
}
