package acme

import (
	"fmt"

	"github.com/labstack/echo/v4"
)

func (s *Server) acmeURL(projectID string) string {
	return fmt.Sprintf("%s/acme/%s", s.addr, projectID)
}

func (s *ACMEServer) directoryURL(c echo.Context) string {
	return fmt.Sprintf("%s/%s/directory", s.addr, c.(*Context).project.ID)
}

func (s *ACMEServer) newNonceURL(c echo.Context) string {
	return fmt.Sprintf("%s/%s/new-nonce", s.addr, c.(*Context).project.ID)
}

func (s *ACMEServer) newAccountURL(c echo.Context) string {
	return fmt.Sprintf("%s/%s/new-account", s.addr, c.(*Context).project.ID)
}

func (s *ACMEServer) newOrderURL(c echo.Context) string {
	return fmt.Sprintf("%s/%s/new-order", s.addr, c.(*Context).project.ID)
}

func (s *ACMEServer) newAuthzURL(c echo.Context) string {
	return fmt.Sprintf("%s/%s/new-authz", s.addr, c.(*Context).project.ID)
}

func (s *ACMEServer) revokeCertURL(c echo.Context) string {
	return fmt.Sprintf("%s/%s/revoke-cert", s.addr, c.(*Context).project.ID)
}

func (s *ACMEServer) keyChangeURL(c echo.Context) string {
	return fmt.Sprintf("%s/%s/key-change", s.addr, c.(*Context).project.ID)
}

func (s *ACMEServer) termsURL(c echo.Context) string {
	return fmt.Sprintf("%s/%s/terms/", s.addr, c.(*Context).project.ID)
}

func (s *ACMEServer) websiteURL(c echo.Context) string {
	return fmt.Sprintf("%s/%s/site/", s.addr, c.(*Context).project.ID)
}

func (s *ACMEServer) accountURL(c echo.Context, accountID string) string {
	return fmt.Sprintf("%s/%s/accounts/%s", s.addr, c.(*Context).project.ID, accountID)
}

func (s *ACMEServer) accountOrderListURL(c echo.Context, accountID string) string {
	return fmt.Sprintf("%s/%s/accounts/%s/orders", s.addr, c.(*Context).project.ID, accountID)
}

func (s *ACMEServer) orderURL(c echo.Context, orderID string) string {
	return fmt.Sprintf("%s/%s/orders/%s", s.addr, c.(*Context).project.ID, orderID)
}

func (s *ACMEServer) finalizeURL(c echo.Context, orderID string) string {
	return fmt.Sprintf("%s/%s/orders/%s/finalize", s.addr, c.(*Context).project.ID, orderID)
}

func (s *ACMEServer) authzURL(c echo.Context, authzID string) string {
	return fmt.Sprintf("%s/%s/authz/%s", s.addr, c.(*Context).project.ID, authzID)
}

func (s *ACMEServer) certificateURL(c echo.Context, certID string) string {
	if certID == "" {
		return ""
	}

	return fmt.Sprintf("%s/%s/certs/%s", s.addr, c.(*Context).project.ID, certID)
}

func (s *ACMEServer) challengeURL(c echo.Context, ID string) string {
	return fmt.Sprintf("%s/%s/challenges/%s", s.addr, c.(*Context).project.ID, ID)
}
