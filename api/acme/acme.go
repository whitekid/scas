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
	"scas/pkg/helper"
)

// Server represents ACME server
//
// TODO integrated with scas server
type Server struct {
	manager *manager.Manager
	addr    string

	acme *ACMEServer
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

	payload   []byte
	header    acmeclient.JOSEHeader
	account   *store.Account // current account information if requested with KID header
	projectID string
	project   *store.Project // valid if request has :project_id parameter
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
	e.Use(customContext)
	e.Use(s.errorHandler)

	extractProjectID := helper.ExtractParam("project_id", func(c echo.Context, val string) { c.(*Context).projectID = val })

	e.Use(extractProjectID)

	s.acme = &ACMEServer{
		manager: s.manager,
	}

	e.POST("/", s.createProject)
	e.GET("/:project_id", s.getProject, s.acme.checkValidProject)
	e.POST("/:project_id/terms", s.createTerm, s.acme.checkValidProject)
	e.POST("/:project_id/terms/:term_id", s.updateTerm, s.acme.checkValidProject)
	e.GET("/:project_id/terms/:term_id", s.getTerm, s.acme.checkValidProject)
	e.GET("/:project_id/terms", s.getTerm, s.acme.checkValidProject)

	acme := e.Group("/acme/:project_id", extractProjectID, s.acme.checkValidProject)
	acme.GET("/directory", s.acme.getDirectory)
	acme.HEAD("/new-nonce", s.acme.newNonce, s.acme.addNonce)
	acme.POST("/new-account", s.acme.newAccount, s.acme.parseJOSERequest, s.acme.addNonce)
	acme.GET("/new-account", s.methodNotAllowed)
	acme.POST("/accounts/:acct_id", s.acme.updateAccount, s.acme.parseJOSERequest, s.acme.checkValidAccount, s.extractAccountID, s.acme.addNonce)
	acme.GET("/accounts/:acct_id", s.methodNotAllowed)
	acme.POST("/accounts/:acct_id/orders", s.notImplemented, s.acme.parseJOSERequest, s.acme.checkValidAccount, s.extractAccountID, s.acme.addNonce)
	acme.GET("/accounts/:acct_id/orders", s.methodNotAllowed)
	acme.POST("/new-order", s.acme.newOrder, s.acme.parseJOSERequest, s.acme.checkValidAccount, s.acme.addNonce)
	acme.GET("/new-order", s.methodNotAllowed)
	acme.POST("/authz/:auth_id", s.acme.authorize, s.acme.parseJOSERequest, s.acme.checkValidAccount, s.acme.addNonce)
	acme.GET("/authz/:auth_id", s.methodNotAllowed)
	acme.POST("/challenges/:challenge_id", s.acme.challenge, s.acme.parseJOSERequest, s.acme.checkValidAccount, s.acme.addNonce)
	acme.GET("/challenges/:challenge_id", s.methodNotAllowed)
	acme.POST("/orders/:order_id/finalize", s.acme.finalizeOrder, s.acme.parseJOSERequest, s.acme.checkValidAccount, s.acme.addNonce)
	acme.GET("/orders/:order_id/finalize", s.methodNotAllowed)
	acme.POST("/certs/:cert_id", s.acme.getCert, s.acme.parseJOSERequest, s.acme.checkValidAccount, s.acme.addNonce)
	acme.GET("/certs/:cert_id", s.methodNotAllowed)
	acme.POST("/revoke-cert", s.acme.revokeCert, s.acme.parseJOSERequest, s.acme.checkValidAccount, s.acme.addNonce)
	acme.GET("/revoke-cert", s.methodNotAllowed)
	acme.POST("/key-change", s.acme.keyChange, s.acme.parseJOSERequest, s.acme.checkValidAccount, s.acme.addNonce)
	acme.GET("/key-change", s.methodNotAllowed)
}

func (s *Server) extractAccountID(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		acctID := c.Param("acct_id")
		cc := c.(*Context)

		// 이미 KID 또는 JWK로 account 정보를 넘겼기 때문에 여기서는 확인만 한다.
		if cc.account.ID != acctID {
			return store.ErrAccountDoesNotExist
		}

		return next(c)
	}
}
func (s *Server) Startup(ctx context.Context, addr string) {
	s.addr = addr
	s.acme.addr = addr + "/acme"

	errCh := make(chan error)

	go fx.CloseChan(ctx, errCh)
	go fx.IterChan(ctx, errCh, func(err error) { log.Errorf("%+v", err) })

	go goxp.Every(ctx, time.Minute, func() error { return s.manager.CheckNonceTimeout(ctx) }, errCh)

	go s.manager.StartChallengeLoop(ctx, errCh)
}

func (s *Server) notImplemented(c echo.Context) error   { panic("Not Implemented") }
func (s *Server) methodNotAllowed(c echo.Context) error { return store.ErrMethodNotAllowed }

type ACMEServer struct {
	manager *manager.Manager
	addr    string
}

func (s *ACMEServer) getDirectory(c echo.Context) error {
	return c.JSON(http.StatusOK, &acmeclient.Directory{
		NewNonce:                s.newNonceURL(c),
		NewAccount:              s.newAccountURL(c),
		NewOrder:                s.newOrderURL(c),
		NewAuthz:                s.newAuthzURL(c),
		RevokeCert:              s.revokeCertURL(c),
		KeyChange:               s.keyChangeURL(c),
		TermOfService:           s.termsURL(c),
		Website:                 s.websiteURL(c),
		CAAIdentities:           c.(*Context).project.CAAIdentities,
		ExternalAccountRequired: c.(*Context).project.ExternalAccountRequired,
	})
}
