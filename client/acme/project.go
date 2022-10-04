package acme

import (
	"context"
	"time"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/request"

	"scas/pkg/helper"
)

func (c *Client) Projects() *ProjectService {
	return &ProjectService{
		client: c,
	}
}

type ProjectService struct {
	client *Client
}

type Project struct {
	ID           string    `json:"id"`
	Name         string    `json:"name" validate:"required"` // project name
	ACMEEndpoint string    `json:"acme_endpoint"`            // ACME endpoint url
	CreatedAt    time.Time `json:"created_at"`
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
	if err := resp.JSON(&proj); err != nil {
		return nil, errors.Wrapf(err, "parse response")
	}

	return &proj, nil
}

func (p *ProjectService) Get(ctx context.Context, projID string) (*Project, error) {
	resp, err := p.client.sendRequest(ctx, request.Get("%s/%s", p.client.endpoint, projID))
	if err != nil {
		return nil, errors.Wrapf(err, "fail to create project")
	}

	var proj Project
	if err := resp.JSON(&proj); err != nil {
		return nil, errors.Wrapf(err, "parse response")
	}

	return &proj, nil
}
