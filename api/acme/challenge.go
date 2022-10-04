package acme

import (
	"bytes"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/whitekid/goxp/log"

	acmeclient "scas/client/acme"
)

func (s *ACMEServer) challenge(c echo.Context) error {
	cc := c.(*Context)
	log.Debugf("challenge(): payload=%s", cc.payload)

	switch {
	case bytes.Equal(cc.payload, []byte{}): // get the challenge resource
		chal, err := s.manager.GetChallenge(c.Request().Context(), c.Param("challenge_id"))
		if err != nil {
			return errors.Wrapf(err, "fail to get challenge")
		}

		// Spec 상에는 Location이 없다. 편의를 위해서 ID를 넣어준다.
		c.Response().Header().Set(echo.HeaderLocation, s.challengeURL(c, chal.ID))
		if chal.RetryAfter != nil {
			c.Response().Header().Set("Retry-After", chal.RetryAfter.String())
		}

		return c.JSON(http.StatusOK, &acmeclient.Challenge{
			Type:      chal.Type,
			URL:       s.challengeURL(c, chal.ID),
			Token:     chal.Token,
			Status:    chal.Status,
			Validated: chal.Validated,
			Error:     chal.Error,
		})

	case bytes.EqualFold(cc.payload, []byte("{}")): // request challenge
		err := s.manager.RequestChallenge(c.Request().Context(), c.Param("challenge_id"))
		if err != nil {
			return errors.Wrapf(err, "fail to request challenge")
		}

		return nil

	default:
		log.Debugf(`payload: %s`, string(cc.payload))
		return echo.ErrBadRequest
	}
}
