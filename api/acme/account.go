package acme

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/mail"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/whitekid/goxp"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/acme/store"
	acmeclient "scas/client/acme"
	"scas/pkg/helper"
)

func (s *ACMEServer) newAccount(c echo.Context) error {
	log.Debugf("newAccount()")

	cc := c.(*Context)

	req := &acmeclient.AccountRequest{}
	if err := s.parseJOSEPayload(c, req); err != nil {
		return err
	}

	if err := s.validateAccountRequest(req); err != nil {
		return err
	}

	acct, created, err := s.manager.NewAccount(c.Request().Context(), cc.projectID, cc.header.JWK, cc.header.KID, req)
	if err != nil {
		return errors.Wrapf(err, "fail to create account")
	}

	acct.Orders = s.accountOrderListURL(c, acct.ID)

	c.Response().Header().Set(echo.HeaderLocation, s.accountURL(c, acct.ID))
	return c.JSON(goxp.Ternary(created, http.StatusCreated, http.StatusOK), &acct.AccountResource)
}

func (s *ACMEServer) validateAccountRequest(req *acmeclient.AccountRequest) error {
	allowedEmailDomains := []string{"@example.com"} // TODO project 마다 다른 설정으로 가야지...

	// validate contact
	for _, contact := range req.Contact {
		if !strings.HasPrefix(contact, "mailto:") {
			return store.ErrUnsupportedContact
		}

		addr, err := mail.ParseAddress(contact[7:])
		if err != nil {
			return store.ErrInvalidContact
		}

		parts := strings.Split(addr.Address, "@")
		domain := parts[len(parts)-1]

		if !fx.Contains(allowedEmailDomains, "@"+domain) {
			return store.ErrInvalidContact
		}
	}

	return nil
}

func (s *ACMEServer) updateAccount(c echo.Context) error {
	log.Debugf("updateAccount()")

	cc := c.(*Context)

	var deactiveReq acmeclient.DeactiveRequest
	if err := json.Unmarshal(cc.payload, &deactiveReq); err == nil && deactiveReq.Status != "" {
		if err := helper.ValidateStruct(&deactiveReq); err != nil {
			return err
		}

		if _, err := s.manager.DeactivateAccount(c.Request().Context(), cc.project.ID, cc.account.ID); err != nil {
			return err
		}

		return nil
	}

	var updateReq acmeclient.AccountRequest
	if err := json.Unmarshal(cc.payload, &updateReq); err == nil {
		if err := helper.ValidateStruct(&updateReq); err != nil {
			return err
		}

		if err := s.validateAccountRequest(&updateReq); err != nil {
			return err
		}

		acct, err := s.manager.UpdateAccount(c.Request().Context(), cc.project.ID, cc.account.ID, updateReq.Contact)
		if err != nil {
			return err
		}

		acct.Orders = s.accountOrderListURL(c, acct.ID)

		c.Response().Header().Set(echo.HeaderLocation, s.accountURL(c, acct.ID))
		return c.JSON(http.StatusOK, &acct.AccountResource)
	}

	return store.ErrMalformed
}

func (s *ACMEServer) keyChange(c echo.Context) error {
	var req acmeclient.JOSERequest

	if err := s.parseJOSEPayload(c, &req); err != nil {
		return err
	}

	var header acmeclient.JOSEHeader
	headerBytes, err := base64.RawURLEncoding.DecodeString(req.Protected)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return err
	}

	if err := helper.ValidateStruct(&header); err != nil {
		return err
	}

	var keyChange acmeclient.KeyChange
	payloadBytes, err := base64.RawURLEncoding.DecodeString(req.Payload)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payloadBytes, &keyChange); err != nil {
		return err
	}

	if err := helper.ValidateStruct(&keyChange); err != nil {
		return err
	}

	if header.URL != c.(*Context).header.URL {
		return errors.Errorf("url mismatch: %s, %s", header.URL, c.(*Context).header.URL)
	}

	// check inner signature
	cc := c.(*Context)
	if _, err := s.manager.VerifySignature(c.Request().Context(), cc.project.ID, header.JWK, "", req.Signature, req.Protected, req.Payload); err != nil {
		return err
	}

	if _, err := s.manager.UpdateAccountKey(c.Request().Context(), cc.project.ID, keyChange.OldKey, header.JWK); err != nil {
		return err
	}

	return nil
}
