package acme

import (
	"fmt"
)

func (s *Server) directoryURL() string  { return fmt.Sprintf("%s/directory", s.addr) }
func (s *Server) newNonceURL() string   { return fmt.Sprintf("%s/new-nonce", s.addr) }
func (s *Server) newAccountURL() string { return fmt.Sprintf("%s/new-account", s.addr) }
func (s *Server) newOrderURL() string   { return fmt.Sprintf("%s/new-order", s.addr) }
func (s *Server) newAuthzURL() string   { return fmt.Sprintf("%s/new-authz", s.addr) }
func (s *Server) revokeCertURL() string { return fmt.Sprintf("%s/revoke-cert", s.addr) }
func (s *Server) keyChangeURL() string  { return fmt.Sprintf("%s/key-change", s.addr) }
func (s *Server) termsURL() string      { return fmt.Sprintf("%s/terms/2022-09-14", s.addr) }
func (s *Server) websiteURL() string    { return s.addr }

func (s *Server) accountURL(accountID string) string {
	return fmt.Sprintf("%s/accounts/%s", s.addr, accountID)
}

func (s *Server) accountOrderListURL(accountID string) string {
	return fmt.Sprintf("%s/accounts/%s/orders", s.addr, accountID)
}

func (s *Server) orderURL(orderID string) string {
	return fmt.Sprintf("%s/orders/%s", s.addr, orderID)
}

func (s *Server) finalizeURL(orderID string) string {
	return fmt.Sprintf("%s/orders/%s/finalize", s.addr, orderID)
}

func (s *Server) authzURL(authzID string) string {
	return fmt.Sprintf("%s/authz/%s", s.addr, authzID)
}

func (s *Server) certificateURL(certID string) string {
	if certID == "" {
		return ""
	}

	return fmt.Sprintf("%s/certs/%s", s.addr, certID)
}

func (s *Server) challengeURL(ID string) string {
	return fmt.Sprintf("%s/challenges/%s", s.addr, ID)
}
