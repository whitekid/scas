package acme

import (
	"crypto/x509"
	"encoding/base64"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/acme/store"
	acmeclient "scas/client/acme"
)

func (s *ACMEServer) newOrder(c echo.Context) error {
	cc := c.(*Context)

	req := &acmeclient.OrderRequest{}
	if err := s.parseJOSEPayload(c, req); err != nil {
		return err
	}

	order, err := s.manager.NewOrder(c.Request().Context(), cc.header.KID, req.Identifiers, req.NotBefore, req.NotAfter)
	if err != nil {
		return errors.Wrapf(err, "fail to create order")
	}

	order.Finalize = s.finalizeURL(c, order.ID)
	order.Authz = fx.Map(order.Authz, func(id string) string { return s.authzURL(c, id) })
	order.Certificate = s.certificateURL(c, order.Certificate)

	c.Response().Header().Set(echo.HeaderLocation, s.orderURL(c, order.ID))
	return c.JSON(http.StatusCreated, &order.OrderResource)
}

func (s *ACMEServer) finalizeOrder(c echo.Context) error {
	log.Debugf("finalizeOrder()")

	req := &acmeclient.FinalizeRequest{}
	if err := s.parseJOSEPayload(c, req); err != nil {
		return err
	}

	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		return store.ErrJOSEPayloadDecodeFail
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return errors.Wrap(store.ErrBadCSR, err.Error())
	}

	order, err := s.manager.FinalizeOrder(c.Request().Context(), c.Param("order_id"), csr)
	if err != nil {
		return errors.Wrapf(err, "fail to finalize order")
	}

	order.Certificate = s.certificateURL(c, order.Certificate)

	c.Response().Header().Set(echo.HeaderLocation, order.Location)
	return c.JSON(http.StatusOK, order)
}

func (s *ACMEServer) authorize(c echo.Context) error {
	authz, err := s.manager.Authorize(c.Request().Context(), c.Param("auth_id"))
	if err != nil {
		return errors.Wrapf(err, "fail to get authorization")
	}

	for _, chal := range authz.Challenges {
		chal.URL = s.challengeURL(c, chal.ID)
	}

	// Spec 상에는 Location이 없다. 편의를 위해서 ID를 넣어준다.
	c.Response().Header().Set(echo.HeaderLocation, s.authzURL(c, authz.ID))
	return c.JSON(http.StatusOK, &acmeclient.AuthzResource{
		Status:     authz.Status,
		Expires:    authz.Expires,
		Identifier: authz.Identifier,
		Challenges: fx.Map(authz.Challenges, func(ch *store.Challenge) *acmeclient.Challenge {
			return &acmeclient.Challenge{
				Type:      ch.Type,
				URL:       s.challengeURL(c, ch.ID),
				Token:     ch.Token,
				Status:    ch.Status,
				Validated: ch.Validated,
				Error:     ch.Error,
			}
		}),
		Wildcard: authz.Wildcard,
	})
}
