package client

import (
	"net/http"

	"scas/client/v1alpha1"
)

func New(endpoint string) *Client { return WithClient(endpoint, &http.Client{}) }
func WithClient(endpoint string, client *http.Client) *Client {
	return &Client{
		endpoint: endpoint,
		client:   client,
		v1Alpha1: v1alpha1.WithClient(endpoint+"/v1alpha1", client),
	}
}

type Client struct {
	endpoint string
	client   *http.Client

	v1Alpha1 *v1alpha1.Client
}

func (c *Client) V1Alpha1() *v1alpha1.Client { return c.v1Alpha1 }
