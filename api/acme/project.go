package acme

import (
	"crypto/x509"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/whitekid/goxp"
	"github.com/whitekid/goxp/fx"

	"scas/acme/store"
	acmeclient "scas/client/acme"
	"scas/pkg/helper"
	"scas/pkg/helper/x509x"
)

func (s *Server) createProject(c echo.Context) error {
	var req acmeclient.Project

	if err := helper.Bind(c, &req); err != nil {
		return err
	}

	proj, err := s.manager.CreateProject(c.Request().Context(), &store.Project{
		Name:               req.Name,
		Website:            req.Website,
		CommonName:         req.CommonName,
		Country:            req.Country,
		Organization:       req.Organization,
		OrganizationalUnit: req.OrganizationalUnit,
		Locality:           req.Locality,
		Province:           req.Province,
		StreetAddress:      req.StreetAddress,
		PostalCode:         req.PostalCode,
		KeyUsage:           x509x.StrToKeyUsage(req.KeyUsage),
		ExtKeyUsage:        fx.Map(req.ExtKeyUsage, func(s string) x509.ExtKeyUsage { return x509x.StrToExtKeyUsage(s) }),
		UseRemoteCA:        req.UseRemoteCA,
		RemoteCAEndpoint:   req.RemoteCAEndpoint,
		RemoteCAProjectID:  req.RemoteCAProjectID,
		RemoteCAID:         req.RemoteCAID,
	})
	if err != nil {
		return errors.Wrapf(err, "fail to create project") // TODO error handling
	}

	return c.JSON(http.StatusOK, s.projectToResouce(proj))
}

func (s *Server) projectToResouce(in *store.Project) *acmeclient.Project {
	return &acmeclient.Project{
		ID:                 in.ID,
		Name:               in.Name,
		TermID:             in.TermID,
		Website:            in.Website,
		ACMEEndpoint:       s.acmeURL(in.ID),
		CreatedAt:          in.CreatedAt,
		CommonName:         in.CommonName,
		Country:            in.Country,
		Organization:       in.Organization,
		OrganizationalUnit: in.OrganizationalUnit,
		Locality:           in.Locality,
		Province:           in.Province,
		StreetAddress:      in.StreetAddress,
		PostalCode:         in.PostalCode,
		KeyUsage:           x509x.KeyUsageToStr(in.KeyUsage),
		ExtKeyUsage:        goxp.Ternary(len(in.ExtKeyUsage) > 0, fx.Map(in.ExtKeyUsage, func(x x509.ExtKeyUsage) string { return x509x.ExtKeyUsageToStr(x) }), nil),
		UseRemoteCA:        in.UseRemoteCA,
		RemoteCAEndpoint:   in.RemoteCAEndpoint,
		RemoteCAProjectID:  in.RemoteCAProjectID,
		RemoteCAID:         in.RemoteCAID,
	}
}

func (s *Server) getProject(c echo.Context) error {
	cc := c.(*Context)

	proj, err := s.manager.GetProject(c.Request().Context(), cc.projectID)
	if err != nil {
		return errors.Wrapf(err, "fail to get project") // TODO error handling
	}

	return c.JSON(http.StatusOK, s.projectToResouce(proj))
}
