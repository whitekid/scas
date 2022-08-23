package helper

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func StartEcho(ctx context.Context, e *Echo, addr string) error {
	go func() {
		<-ctx.Done()
		e.Shutdown(context.Background())
	}()

	if err := e.Start(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

type Echo struct {
	*echo.Echo
}

// NewEcho create new default echo handlers
//
// TODO move to goxp
func NewEcho(middlewares ...echo.MiddlewareFunc) *Echo {
	e := echo.New()
	e.HideBanner = true
	e.Validator = &echoValidator{validator: validate}
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.Logger())
	e.Use(middleware.RequestID())
	e.Use(LogErrors())
	e.Use(middlewares...)

	return &Echo{e}
}

// Middlewares

// LogErrors log error when http status error occurred
func LogErrors() echo.MiddlewareFunc { return LogErrorsWithCode(http.StatusBadGateway) }
func LogErrorsWithCode(logCode int) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		// log http errors
		return func(c echo.Context) error {
			err := next(c)
			if err != nil {
				code := http.StatusInternalServerError

				if ee, ok := err.(validator.ValidationErrors); ok {
					err = echo.NewHTTPError(http.StatusBadRequest, ee.Error())
				}

				if he, ok := err.(*echo.HTTPError); ok {
					code = he.Code
				}

				if code >= logCode {
					c.Logger().Errorf("%+v", err)
				}
			}

			return err
		}
	}
}

func ExtractHeader(header string, fn func(c echo.Context, cval string)) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			fn(c, c.Request().Header.Get(header))

			return next(c)
		}
	}
}

// ExtractParam extract path parameter and callback to use custom context
// Usage:
// 	e.Use(ExtractParam("project_id", func(c echo.Context, val string) { c.(*Context).projectID = val }))

func ExtractParam(param string, callback func(c echo.Context, val string)) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			callback(c, c.Param(param))

			return next(c)
		}
	}
}

// Bind bind & validate
func Bind(c echo.Context, val interface{}) error {
	if err := c.Bind(val); err != nil {
		return echo.ErrBadRequest
	}

	if err := c.Validate(val); err != nil {
		return err
	}

	return nil
}

type echoValidator struct {
	validator *validator.Validate
}

func (v *echoValidator) Validate(i interface{}) error {
	if err := v.validator.Struct(i); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}

func NewHTTPError(code int, msg ...interface{}) error {
	if len(msg) > 2 {
		return echo.NewHTTPError(code, fmt.Sprintf(msg[0].(string), msg[1:]...))
	}

	return echo.NewHTTPError(code, msg...)
}
