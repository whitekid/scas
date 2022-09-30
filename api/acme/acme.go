package acme

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/whitekid/goxp"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/acme/manager"
	"scas/acme/store"
	"scas/api/endpoints"
	acmeclient "scas/client/acme"
)

// Server represents ACME server
//
// TODO integrated with scas server
type Server struct {
	manager *manager.Manager
	addr    string
}

var (
	_ endpoints.Endpoint = (*Server)(nil)
)

func New(dburi string) *Server {
	return &Server{
		manager: manager.New(store.NewSQLStore(dburi)),
	}
}

func (s *Server) PathAndName() (string, string) { return "/acme", "acme handler" }

type Context struct {
	echo.Context

	payload []byte
	header  acmeclient.JOSEHeader
}

func customContext(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		cc, ok := c.(*Context)
		if !ok {
			cc = &Context{Context: c}
		}
		return next(cc)
	}
}

func (s *Server) Route(e *echo.Group) {
	e.Use(s.errorHandler)

	e.GET("/directory", s.getDirectory)
	e.HEAD("/new-nonce", s.newNonce, s.addNonce)
	e.POST("/new-account", s.newAccount, customContext, s.addNonce, s.parseJOSERequest)
	e.GET("/new-account", s.malformed)
	e.POST("/accounts/:acct_id", s.updateAccount, customContext, s.parseJOSERequest, s.addNonce)
	e.GET("/accounts/:acct_id", s.malformed)
	e.POST("/accounts/:acct_id/orders", s.notImplemented, customContext, s.parseJOSERequest, s.addNonce)
	e.GET("/accounts/:acct_id/orders", s.malformed)
	e.POST("/new-order", s.newOrder, customContext, s.parseJOSERequest, s.addNonce)
	e.GET("/new-order", s.malformed)
	e.POST("/authz/:auth_id", s.authorize, customContext, s.parseJOSERequest, s.addNonce)
	e.GET("/authz/:auth_id", s.malformed)
	e.POST("/challenges/:challenge_id", s.challenge, customContext, s.parseJOSERequest, s.addNonce)
	e.GET("/challenges/:challenge_id", s.malformed)
	e.POST("/orders/:order_id/finalize", s.finalizeOrder, customContext, s.parseJOSERequest, s.addNonce)
	e.GET("/orders/:order_id/finalize", s.malformed)
	e.POST("/certs/:cert_id", s.getCert, customContext, s.parseJOSERequest, s.addNonce)
	e.GET("/certs/:cert_id", s.malformed)
	e.POST("/revoke-cert", s.revokeCert, customContext, s.parseJOSERequest, s.addNonce)
	e.GET("/revoke-cert", s.malformed)
	e.POST("/key-change", s.keyChange, customContext, s.parseJOSERequest, s.addNonce)
	e.GET("/key-change", s.malformed)
}

func (s *Server) Startup(ctx context.Context) {
	errCh := make(chan error)

	go fx.CloseChan(ctx, errCh)
	go fx.IterChan(ctx, errCh, func(err error) { log.Errorf("%+v", err) })

	go goxp.Every(ctx, time.Minute, func() error { return s.manager.CheckNonceTimeout(ctx) }, errCh)

	go s.manager.StartChallengeLoop(ctx, errCh)
}

func (s *Server) notImplemented(c echo.Context) error { panic("Not Implemented") }
func (s *Server) malformed(c echo.Context) error      { return store.ErrMalformed }

func (s *Server) getDirectory(c echo.Context) error {
	return c.JSON(http.StatusOK, &acmeclient.Directory{
		NewNonce:                s.newNonceURL(),
		NewAccount:              s.newAccountURL(),
		NewOrder:                s.newOrderURL(),
		NewAuthz:                s.newAuthzURL(),
		RevokeCert:              s.revokeCertURL(),
		KeyChange:               s.keyChangeURL(),
		TermOfService:           s.termsURL(), // TODO
		Website:                 s.websiteURL(),
		CAAIdentities:           []string{"example.com"}, // TODO
		ExternalAccountRequired: false,                   // TODO
	})
}
