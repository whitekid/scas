package acme

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/whitekid/goxp/log"
)

const (
	HeaderReplayNonce = "Replay-Nonce"
	nonceTimeout      = time.Minute * 30
)

func (s *ACMEServer) addNonce(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if 200 <= c.Response().Status && c.Response().Status < 300 {
			nonce, err := s.manager.NewNonce(c.Request().Context(), c.(*Context).projectID)
			if err != nil {
				return errors.Wrapf(err, "fail to create nonce")
			}

			c.Response().Header().Set(HeaderReplayNonce, nonce)
			log.Debugf("add nonce header: %s", nonce)
		}

		return next(c)
	}
}

func (s *ACMEServer) newNonce(c echo.Context) error {
	header := c.Response().Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Link", s.directoryURL(c))
	return c.NoContent(http.StatusOK)
}
