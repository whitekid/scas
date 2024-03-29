package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/http"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/log"

	"scas/pkg/helper/x509x"
)

//	AccountResource
//
// example:
//
//	  "status": "valid",
//	  "contact": [
//		  "mailto:cert-admin@example.org",
//		  "mailto:admin@example.org"
//	  ],
//	  "termsOfServiceAgreed": true,
//	    "orders": "https://example.com/acme/orders/rzGoeA"
//	  }
type AccountResource struct {
	Status                 AccountStatus `json:"status" validate:"required"`            // Valid, Deactivated, Revoked
	Contact                []string      `json:"contact,omitempty" validate:"required"` // Contact informations
	TermOfServiceAgreed    bool          `json:"termOfServiceAgreeded,omitempty"`
	ExternalAccountBinding struct{}      `json:"externalAccountBinding,omitempty"`
	Orders                 string        `json:"orders,omitempty"` // URL of orders

}

type Account struct {
	AccountResource

	ID       string
	Location string
}

func (a *Account) SetLocation(loc string) {
	a.Location = loc
	a.ID = idFromURI(loc)
}

type AccountStatus string

const (
	AccountStatusValid       AccountStatus = "valid"
	AccountStatusDeactivated AccountStatus = "deactivated"
	AccountStatusRevoked     AccountStatus = "revoked"
)

func (s AccountStatus) String() string { return string(s) }

type AccountRequest struct {
	Contact             []string `json:"contact,omitempty" validate:"required"`
	TermOfServiceAgreed bool     `json:"termOfServiceAgreed,omitempty"`
	OnlyReturnExisting  bool     `json:"onlyReturnExisting,omitempty"`
}

func (client *ACMEClient) NewAccount(ctx context.Context, req *AccountRequest) (*Account, error) {
	resp, err := client.sendJOSERequest(ctx, http.MethodPost, client.directory.NewAccount, req)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to request new account")
	}

	account := &Account{}
	defer resp.Body.Close()
	if err := resp.JSON(&account.AccountResource); err != nil {
		return nil, errors.Wrap(err, "fail to parse response")
	}

	account.SetLocation(resp.Header.Get(headerLocation))
	client.account = account
	return account, nil
}

func (client *ACMEClient) Account(endpoint string) *AccountService {
	return &AccountService{
		client:   client,
		endpoint: endpoint,
	}
}

type AccountService struct {
	client   *ACMEClient
	endpoint string
}

func (svc *AccountService) Update(ctx context.Context, req *AccountRequest) (*Account, error) {
	log.Debugf("Update(): req=%v", req)

	resp, err := svc.client.sendJOSERequest(ctx, http.MethodPost, svc.endpoint, req)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to request update account")
	}

	account := &Account{}
	defer resp.Body.Close()
	if err := resp.JSON(&account.AccountResource); err != nil {
		return nil, errors.Wrap(err, "fail to parse response")
	}

	account.SetLocation(resp.Header.Get(headerLocation))
	svc.client.account = account
	return account, nil
}

type KeyChange struct {
	Account string `json:"account" validate:"required"` // URL for account being modified
	OldKey  string `json:"oldKey" validate:"required"`  // The JWK of the old key
}

func (svc *AccountService) KeyChange(ctx context.Context) error {
	priv, err := x509x.GenerateKey(x509.ECDSAWithSHA256)
	if err != nil {
		return err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return errors.Wrapf(err, "fail to get public key")
	}

	payload, err := svc.client.newJOSERequest(svc.client.directory.KeyChange, &KeyChange{
		Account: svc.client.account.Location,
		OldKey:  base64.RawURLEncoding.EncodeToString(svc.client.pub),
	}, priv, pubBytes)
	if err != nil {
		return errors.Wrapf(err, "fail to request key change")
	}

	resp, err := svc.client.sendJOSERequest(ctx, http.MethodPost, svc.client.directory.KeyChange, payload)
	if err != nil {
		return errors.Wrapf(err, "fail to request key change")
	}

	if !resp.Success() {
		return errors.Errorf("failed with status %d", resp.StatusCode)
	}

	svc.client.key = priv
	svc.client.pub = pubBytes

	return nil
}

type DeactiveRequest struct {
	Status string `json:"status" validate:"required"`
}

func (svc *AccountService) Deactive(ctx context.Context) error {
	_, err := svc.client.sendJOSERequest(ctx, http.MethodPost, svc.endpoint, &DeactiveRequest{
		Status: AccountStatusDeactivated.String(),
	})

	if err != nil {
		return errors.Wrapf(err, "fail to request deactive")
	}

	return nil
}
