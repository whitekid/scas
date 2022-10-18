package v1alpha1

import (
	"context"
	"crypto/x509"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/whitekid/goxp/log"
	"github.com/whitekid/goxp/request"

	"scas/client/common"
	"scas/client/common/x509types"
)

func New(endpoint string) *Client { return WithClient(endpoint, &http.Client{}) }
func WithClient(endpoint string, client *http.Client) *Client {
	c := &Client{
		endpoint: endpoint,
		client:   request.NewSession(client),
	}

	return c
}

type Client struct {
	endpoint string
	client   request.Interface
}

func (c *Client) Projects(projectID string) *ProjectService {
	return &ProjectService{client: c, endpoint: c.endpoint + "/" + projectID}
}

func (c *Client) sendRequest(ctx context.Context, req *request.Request) (*request.Response, error) {
	log.Debugf("send request: %s", req.URL)

	resp, err := req.Do(ctx)
	if err != nil {
		return nil, err
	}

	if !resp.Success() {
		return resp, NewHTTPError(resp.StatusCode, "failed with status %d", resp.StatusCode)
	}

	return resp, nil
}

type ProjectService struct {
	client   *Client
	endpoint string
}

type Project struct {
	ID      string `json:",omitempty"`
	Name    string `validate:"required"`
	Created *common.Timestamp
}

func (svc *ProjectService) Create(ctx context.Context, project *Project) (*Project, error) {
	resp, err := svc.client.sendRequest(ctx, svc.client.client.Post("%s", svc.endpoint).JSON(project))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	var created Project
	if err := resp.JSON(&created); err != nil {
		return nil, err
	}

	return &created, nil
}

type ProjectList struct {
	Items []*Project
}

func (svc *ProjectService) List(ctx context.Context) (*ProjectList, error) {
	resp, err := svc.client.sendRequest(ctx, svc.client.client.Get("%s", svc.endpoint))
	if err != nil {
		return nil, err
	}

	var list ProjectList

	defer resp.Body.Close()
	if err := resp.JSON(&list); err != nil {
		return nil, err
	}

	return &list, nil
}

type CA struct {
	ID      string
	Created *common.Timestamp
	Root    bool // true if root ca
}

func (svc *ProjectService) Certificates() *CertificateService {
	return &CertificateService{client: svc.client, endpoint: svc.endpoint + "/certificates"}
}

type CertificateRequest struct {
	ID   string `json:",omitempty"`
	CAID string `json:",omitempty"` // CA ID

	SerialNumber *big.Int `json:",omitempty"`
	CommonName   string   `json:",omitempty" validate:"required"` // Common Name

	// Names; some part of pkix.Name
	Country            string `json:",omitempty"`
	Province           string `json:",omitempty"` // State or Province
	Locality           string `json:",omitempty"`
	StreetAddress      string `json:",omitempty"`
	PostalCode         string `json:",omitempty"`
	Organization       string `json:",omitempty"` // Organization Name
	OrganizationalUnit string `json:",omitempty"` // Organization Unit Name

	Hosts []string `json:",omitempty"` // DNS Name and IP Addresse

	KeyAlgorithm       x509types.SignatureAlgorithm `json:",omitempty" validate:"required"`
	SignatureAlgorithm x509types.SignatureAlgorithm `json:",omitempty"`
	KeyUsage           x509.KeyUsage
	ExtKeyUsage        []x509.ExtKeyUsage
	NotAfter           time.Time `json:",omitempty" validate:"required"`
	NotBefore          time.Time `json:",omitempty" validate:"required"`

	CRL string `json:",omitempty"`
}

func (svc *ProjectService) CA() *CAService {
	return &CAService{client: svc.client, endpoint: svc.endpoint + "/ca"}
}

func (svc *ProjectService) GetCRL(ctx context.Context) ([]byte, error) {
	req := svc.client.client.Get("%s/crl", svc.endpoint)
	resp, err := svc.client.sendRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, err
}

type CAService struct {
	client   *Client
	endpoint string
}

func (svc *CAService) Create(ctx context.Context, req *CertificateRequest) (*CertificateRequest, error) {
	log.Debugf("CAService.Create(): %+v", req)
	resp, err := svc.client.sendRequest(ctx, svc.client.client.Post("%s", svc.endpoint).JSON(req))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	var csr CertificateRequest
	if err := resp.JSON(&csr); err != nil {
		return nil, err
	}

	return &csr, nil
}

func (svc *CAService) Get(ctx context.Context, ID string) (*CertificateRequest, error) {
	resp, err := svc.client.sendRequest(ctx, svc.client.client.Get("%s/%s", svc.endpoint, ID))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	var csr CertificateRequest
	if err := resp.JSON(&csr); err != nil {
		return nil, err
	}

	return &csr, nil
}

type CertificateList struct {
	Items []*Certificate
}

type Certificate struct {
	ID     string
	Status common.Status
	CAID   string

	// PEM bytes
	TlsCrtPEM   []byte `json:"tls.crt,omitempty"`
	TlsKeyPEM   []byte `json:"tls.key,omitempty"`
	ChainCrtPEM []byte `json:"chain.crt,omitempty"`
}

type CertificateService struct {
	client   *Client
	endpoint string
}

func (svc *CertificateService) Create(ctx context.Context, req *CertificateRequest) (*Certificate, error) {
	resp, err := svc.client.sendRequest(ctx, svc.client.client.Post("%s", svc.endpoint).JSON(req))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	var cert Certificate
	if err := resp.JSON(&cert); err != nil {
		return nil, err
	}

	return &cert, nil
}

func (svc *CertificateService) Get(ctx context.Context, ID string) (*Certificate, error) {
	resp, err := svc.client.sendRequest(ctx, svc.client.client.Get("%s/%s", svc.endpoint, ID))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	var cert Certificate
	if err := resp.JSON(&cert); err != nil {
		return nil, err
	}

	return &cert, nil
}

// List list certificates
func (svc *CertificateService) List(ctx context.Context) (*CertificateList, error) {
	resp, err := svc.client.sendRequest(ctx, svc.client.client.Get("%s", svc.endpoint))
	if err != nil {
		return nil, err
	}

	var list CertificateList

	defer resp.Body.Close()
	if err := resp.JSON(&list); err != nil {
		return nil, err
	}

	return &list, nil
}

type RevokeRequest struct {
	Reason x509types.RevokeReason
}

func (svc *CertificateService) Revoke(ctx context.Context, ID string, reason x509types.RevokeReason) error {
	_, err := svc.client.sendRequest(ctx, svc.client.client.Post("%s/%s/revoke", svc.endpoint, ID).JSON(&RevokeRequest{Reason: reason}))
	if err != nil {
		return err
	}
	return nil
}

func (svc *CertificateService) Renewal(ctx context.Context, ID string) (*Certificate, error) {
	resp, err := svc.client.sendRequest(ctx, svc.client.client.Post("%s/%s/renewal", svc.endpoint, ID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var cert Certificate
	defer resp.Body.Close()
	if err := resp.JSON(&cert); err != nil {
		return nil, err
	}

	return &cert, nil
}
