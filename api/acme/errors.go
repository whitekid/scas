package acme

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"

	"scas/acme/store"
	"scas/client/common"
)

// errorHandler convert errors to acme error, http error
func (s *Server) errorHandler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		err := next(c)
		if err == nil {
			return nil
		}

		var ee *echo.HTTPError

		if errors.As(err, &ee) {
			e := store.NewACMEError(ee.Code, "unknown", ee.Message.(string))
			e.Detail = err.Error()
			return e
		}

		ae := store.ErrToProblem(err)

		// FIXME ...
		if errors.Is(err, store.ErrTermOfServiceChanged) {
			ae = &common.ProblemDetail{
				Type:     store.ErrUserActionRequired.Type,
				Title:    store.ErrUserActionRequired.Title,
				Status:   store.ErrUserActionRequired.Status,
				Instance: s.termsURL(),
			}
		}

		return ae
	}
}

// errorHandler format error
func errorHandler(err error, c echo.Context) {
	code := http.StatusInternalServerError
	var message interface{}

	ae, ok := err.(*common.ProblemDetail)
	if !ok {
		ae = store.ErrServerInternal
	}

	code = ae.Status
	message = ae

	if !c.Response().Committed {
		if c.Request().Method == http.MethodHead {
			c.NoContent(code)
		} else {
			c.Response().Header().Set(echo.HeaderContentType, common.MIMEProblemDetail)
			c.JSON(code, message)
		}
	}
}
