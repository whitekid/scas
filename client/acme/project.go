package acme

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/request"

	"scas/client/common"
	"scas/pkg/helper"
)

func (c *Client) Projects(projID string) *ProjectService {
	return &ProjectService{
		client: c,
		projID: projID,
	}
}

type ProjectService struct {
	client *Client
	projID string
}

type Project struct {
	ID           string    `json:"id"`
	Name         string    `json:"name" validate:"required"` // project name
	TermID       string    `json:"term,omitempty"`
	Website      string    `json:"website"`
	ACMEEndpoint string    `json:"acme_endpoint"` // ACME endpoint url
	CreatedAt    time.Time `json:"created_at"`

	// Issuer subject
	CommonName         string `validate:"required"`
	Country            string
	Organization       string
	OrganizationalUnit string
	Locality           string
	Province           string
	StreetAddress      string
	PostalCode         string
	KeyUsage           string
	ExtKeyUsage        []string
}

func (p *ProjectService) Create(ctx context.Context, req *Project) (*Project, error) {
	if err := helper.ValidateStruct(req); err != nil {
		return nil, err
	}

	resp, err := p.client.sendRequest(ctx, request.Post("%s", p.client.endpoint).JSON(req))
	if err != nil {
		return nil, errors.Wrapf(err, "fail to create project")
	}

	var proj Project
	defer resp.Body.Close()
	if err := resp.JSON(&proj); err != nil {
		return nil, errors.Wrapf(err, "parse response")
	}

	return &proj, nil
}

func (p *ProjectService) Get(ctx context.Context) (*Project, error) {
	resp, err := p.client.sendRequest(ctx, request.Get("%s/%s", p.client.endpoint, p.projID))
	if err != nil {
		return nil, errors.Wrapf(err, "fail to create project")
	}

	var proj Project
	defer resp.Body.Close()
	if err := resp.JSON(&proj); err != nil {
		return nil, errors.Wrapf(err, "parse response")
	}

	return &proj, nil
}

func (p *ProjectService) Term() *TermService {
	return &TermService{
		client:   p.client,
		endpoint: fmt.Sprintf("%s/%s/terms", p.client.endpoint, p.projID),
	}
}

type TermService struct {
	client   *Client
	endpoint string
}

type Term struct {
	ID        string            `json:"id"`
	Content   string            `json:"content" validate:"required"`
	Active    bool              `json:"active,omitempty"`
	CreatedAt *common.Timestamp `json:"created_at"`
	UpdatedAt *common.Timestamp `json:"updated_at"`
}

// Update update term content
func (p *TermService) Update(ctx context.Context, in *Term) (*Term, error) {
	resp, err := p.client.sendRequest(ctx, request.Post(p.endpoint).JSON(in))
	if err != nil {
		return nil, err
	}

	var term Term
	defer resp.Body.Close()
	if err := resp.JSON(&term); err != nil {
		return nil, err
	}

	return &term, err
}

func (p *TermService) Get(ctx context.Context, termID string) (*Term, error) {
	resp, err := p.client.sendRequest(ctx, request.Get("%s/%s", p.endpoint, termID))
	if err != nil {
		return nil, err
	}

	var term Term
	defer resp.Body.Close()
	if err := resp.JSON(&term); err != nil {
		return nil, err
	}

	return &term, nil
}
