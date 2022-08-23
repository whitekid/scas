package acme

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/mail"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/acme/store"
	acmeclient "scas/client/acme"
	"scas/pkg/helper"
)

func (s *Server) newAccount(c echo.Context) error {
	log.Debugf("newAccount()")

	cc := c.(*Context)

	req := &acmeclient.AccountRequest{}
	if err := json.Unmarshal(cc.payload, req); err != nil {
		return errors.Wrap(store.ErrJOSEHeaderDecodeFail, err.Error())
	}

	if err := helper.ValidateStruct(req); err != nil {
		return errors.Wrap(store.ErrJOSEHeaderDecodeFail, err.Error())
	}

	if err := s.validateAccountRequest(req); err != nil {
		return err
	}

	acct, created, err := s.manager.NewAccount(c.Request().Context(), cc.header.JWK, cc.header.KID, req)
	if err != nil {
		return errors.Wrapf(err, "fail to create account")
	}

	acct.Orders = s.accountOrderListURL(acct.ID)

	c.Response().Header().Set(echo.HeaderLocation, s.accountURL(acct.ID))
	return c.JSON(fx.Ternary(created, http.StatusCreated, http.StatusOK), &acct.AccountResource)
}

func (s *Server) validateAccountRequest(req *acmeclient.AccountRequest) error {
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

func (s *Server) updateAccount(c echo.Context) error {
	log.Debugf("updateAccount()")

	cc := c.(*Context)

	req := &acmeclient.AccountRequest{}
	if err := s.parseJOSEPayload(c, req); err != nil {
		return err
	}

	if err := s.validateAccountRequest(req); err != nil {
		return err
	}

	acct, err := s.manager.UpdateAccount(c.Request().Context(), cc.Param("acct_id"), req.Contact)
	if err != nil {
		return err
	}

	acct.Orders = s.accountOrderListURL(acct.ID)

	c.Response().Header().Set(echo.HeaderLocation, s.accountURL(acct.ID))
	return c.JSON(http.StatusOK, &acct.AccountResource)
}

func (s *Server) keyChange(c echo.Context) error {
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
	if err := s.manager.VerifySignature(c.Request().Context(), header.JWK, "", req.Signature, req.Protected, req.Payload); err != nil {
		return err
	}

	if _, err := s.manager.UpdateAccountKey(c.Request().Context(), keyChange.OldKey, header.JWK); err != nil {
		return err
	}

	return nil
}
