package acme

import (
	"crypto/x509"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
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
	})
	if err != nil {
		return errors.Wrapf(err, "fail to create project") // TODO error handling
	}

	return c.JSON(http.StatusOK, &acmeclient.Project{
		ID:           proj.ID,
		Name:         proj.Name,
		ACMEEndpoint: s.acmeURL(proj.ID),
		CreatedAt:    proj.CreatedAt,
	})
}

func (s *Server) getProject(c echo.Context) error {
	cc := c.(*Context)

	proj, err := s.manager.GetProject(c.Request().Context(), cc.projectID)
	if err != nil {
		return errors.Wrapf(err, "fail to get project") // TODO error handling
	}

	return c.JSON(http.StatusOK, &acmeclient.Project{
		ID:           proj.ID,
		Name:         proj.Name,
		TermID:       proj.TermID,
		ACMEEndpoint: s.acmeURL(proj.ID),
		CreatedAt:    proj.CreatedAt,
	})
}
