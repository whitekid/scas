package acme

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

// Cert represents certificate services
func (client *Client) Cert(endpoint string) *CertService {
	return &CertService{
		client:   client,
		endpoint: endpoint,
	}
}

type CertService struct {
	client   *Client
	endpoint string
}

func (svc *CertService) Get(ctx context.Context) ([][]byte, error) {
	resp, err := svc.client.sendJOSERequest(ctx, http.MethodPost, svc.endpoint, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to request download certificate")
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to request download certificate")
	}

	chain := make([][]byte, 0)
	rest := body
	for {
		block, res := pem.Decode(rest)
		if block == nil {
			break
		}
		chain = append(chain, block.Bytes)
		rest = res
	}
	return chain, nil
}
