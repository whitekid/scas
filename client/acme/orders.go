package acme

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net/http"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/log"

	"scas/client/common"
)

// OrderMeta Order metadata

// OrderResource
//
// - status: pending:
//   - 클라이언트가 Expire 시간 안에 Authorization에 설정된 인증을 수행해야 인증서가 발급이 된다.
//   - 클라이언트가 인증에 실패하면, invalid 상태가 되고 order 리소스는 삭제됨
//
// Example:
//
//	  {
//	  	"status": "valid",
//		  "expires": "2016-01-20T14:09:07.99Z",
//		  "identifiers": [
//		    { "type": "dns", "value": "www.example.org" },
//		    { "type": "dns", "value": "example.org" }
//		  ],
//	  	"notBefore": "2016-01-01T00:00:00Z",
//	  	"notAfter": "2016-01-08T00:00:00Z",
//		  "authorizations": [
//		    "https://example.com/acme/authz/PAniVnsZcis",
//		    "https://example.com/acme/authz/r4HqLzrSrpI"
//	  	],
//		"finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize",
//			"certificate": "https://example.com/acme/cert/mAt3xBGaobw"
//		}
type OrderResource struct {
	Status      OrderStatus           `json:"status" validate:"required"`
	Expires     *common.Timestamp     `json:"expires,omitempty"` // required for status pending, valid
	Identifiers []common.Identifier   `json:"identifiers" validate:"required,dive"`
	NotBefore   *common.Timestamp     `json:"notBefore.omitempty"`
	NotAfter    *common.Timestamp     `json:"notAfter.omitempty"`
	Error       *common.ProblemDetail `json:"error,omitempty"`
	Authz       []string              `json:"authorization"`         // authorization URI
	Finalize    string                `json:"finalize"`              // fianlization URI
	Certificate string                `json:"certificate,omitempty"` // certificate URI
}

type Order struct {
	OrderResource `validate:"dive"`

	ID       string `validate:"eq="`
	Location string
}

func (o *Order) SetLocation(loc string) {
	o.Location = loc
	o.ID = idFromURI(loc)
}

type OrderStatus string

const (
	OrderStatusPending    OrderStatus = "pending"
	OrderStatusReady      OrderStatus = "ready"
	OrderStatusProcessing OrderStatus = "processing"
	OrderStatusValid      OrderStatus = "valid"
	OrderStatusInvalid    OrderStatus = "invalid"
)

func (s OrderStatus) String() string { return string(s) }

type OrderRequest struct {
	Identifiers []common.Identifier `json:"identifiers" validator:"required,dive"`
	NotBefore   *common.Timestamp   `json:"notBefore.omitempty"`
	NotAfter    *common.Timestamp   `json:"notAfter.omitempty"`
}

func (client *ACMEClient) NewOrder(ctx context.Context, req *OrderRequest) (*Order, error) {
	resp, err := client.sendJOSERequest(ctx, http.MethodPost, client.directory.NewOrder, req)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to request new order")
	}

	order := &Order{}
	if err := resp.JSON(&order.OrderResource); err != nil {
		return nil, errors.Wrap(err, "fail to parse response")
	}

	u, err := resp.Location()
	if err != nil {
		return nil, errors.Wrap(err, "fail to parse response")
	}
	order.SetLocation(u.String())

	return order, nil
}

func (client *ACMEClient) Order(endpoint string) *OrderService {
	return &OrderService{
		client:   client,
		endpoint: endpoint,
	}
}

type OrderService struct {
	client   *ACMEClient
	endpoint string
}

type FinalizeRequest struct {
	CSR string `json:"csr" validate:"required"` // base64 encoded der format certificate request: rfc2986
}

func (svc *OrderService) Finalize(ctx context.Context, template *x509.CertificateRequest) (*Order, error) {
	log.Debugf("Finalize(): template=%+v", template)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, svc.client.key)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to finaize order")
	}

	req := &FinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	}

	resp, err := svc.client.sendJOSERequest(ctx, http.MethodPost, svc.endpoint, req)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to request update account")
	}

	order := &Order{}
	if err := resp.JSON(&order.OrderResource); err != nil {
		return nil, errors.Wrap(err, "fail to parse response")
	}

	order.SetLocation(resp.Header.Get(headerLocation))

	return order, nil
}
