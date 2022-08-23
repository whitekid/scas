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
func (s *Server) parseJOSERequest(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		req := &acmeclient.JOSERequest{}

		if err := c.Bind(req); err != nil {
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

		if !s.manager.ValidNonce(c.Request().Context(), cc.header.Nonce) {
			return store.ErrBadNonce
		}

		cc.payload, err = base64.RawURLEncoding.DecodeString(req.Payload)
		if err != nil {
			return errors.Wrapf(store.ErrJOSEHeaderDecodeFail, err.Error())
		}

		if err := s.manager.VerifySignature(c.Request().Context(), cc.header.JWK, cc.header.KID, req.Signature, req.Protected, req.Payload); err != nil {
			return err
		}

		return next(c)
	}
}

// parseJOSEPayload parse jose payload to struct and validate
func (s *Server) parseJOSEPayload(c echo.Context, v interface{}) error {
	cc := c.(*Context)

	if err := json.Unmarshal(cc.payload, v); err != nil {
		return errors.Wrapf(store.ErrJOSEPayloadDecodeFail, err.Error())
	}

	if err := helper.ValidateStruct(v); err != nil {
		return errors.Wrapf(store.ErrJOSEPayloadDecodeFail, err.Error())
	}

	return nil
}
