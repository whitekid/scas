package acme

import (
	"encoding/base64"
	"encoding/json"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"

	"scas/acme/store"
	acmeclient "scas/client/acme"
	"scas/pkg/helper"
)

// parseJOSERequest parse JWS and set payload
func (s *ACMEServer) parseJOSERequest(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		req := &acmeclient.JOSERequest{}

		if err := helper.Bind(c, req); err != nil {
			return err
		}

		cc := c.(*Context)
		header, err := base64.RawURLEncoding.DecodeString(req.Protected)
		if err != nil {
			return store.ErrJOSEHeaderDecodeFail
		}

		if err := json.Unmarshal(header, &cc.header); err != nil {
			return store.ErrJOSEHeaderDecodeFail
		}

		ctx := c.Request().Context()
		if !s.manager.ValidNonce(ctx, cc.projectID, cc.header.Nonce) {
			return store.ErrBadNonce
		}

		cc.payload, err = base64.RawURLEncoding.DecodeString(req.Payload)
		if err != nil {
			return errors.Wrapf(store.ErrJOSEHeaderDecodeFail, err.Error())
		}

		acct, err := s.manager.VerifySignature(ctx, cc.project.ID, cc.header.JWK, cc.header.KID, req.Signature, req.Protected, req.Payload)
		if err != nil {
			return err
		}

		cc.account = acct
		return next(c)
	}
}

func (s *ACMEServer) checkValidAccount(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		cc := c.(*Context)

		if cc.header.JWK != "" {
			if acct, err := s.manager.GetAccountByKey(c.Request().Context(), cc.project.ID, cc.header.JWK); err == nil {
				cc.account = acct
			}
		}

		if cc.account != nil {
			if cc.account.Status != acmeclient.AccountStatusValid {
				return echo.ErrUnauthorized
			}
		}

		return next(c)
	}
}

func (s *ACMEServer) checkValidProject(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		cc := c.(*Context)

		if cc.projectID == "" {
			return echo.ErrNotFound
		}

		proj, err := s.manager.GetProject(c.Request().Context(), cc.projectID)
		if err != nil {
			return err
		}

		cc.project = proj

		return next(c)
	}
}

// parseJOSEPayload parse jose payload to struct and validate
func (s *ACMEServer) parseJOSEPayload(c echo.Context, v interface{}) error {
	cc := c.(*Context)

	if err := json.Unmarshal(cc.payload, v); err != nil {
		return errors.Wrapf(store.ErrJOSEPayloadDecodeFail, err.Error())
	}

	if err := helper.ValidateStruct(v); err != nil {
		return errors.Wrapf(store.ErrJOSEPayloadDecodeFail, err.Error())
	}

	return nil
}
