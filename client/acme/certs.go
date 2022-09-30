package acme

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"

	"scas/client/common/x509types"

	"github.com/pkg/errors"
)

// Certificate represents certificate services
func (client *Client) Certificate(endpoint string) *CertService {
	return &CertService{
		client:   client,
		endpoint: endpoint,
	}
}

type CertService struct {
	client   *Client
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
	_, err := svc.client.sendJOSERequest(ctx, http.MethodPost, svc.client.directory.RevokeCert,
		&CertificateRevoke{
			Certificate: base64.RawURLEncoding.EncodeToString(certPEM),
			Reason:      int(reason),
		})
	if err != nil {
		return err
	}

	return nil
}
