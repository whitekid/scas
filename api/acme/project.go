package acme

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"

	acmeclient "scas/client/acme"
	"scas/pkg/helper"
)

func (s *Server) createProject(c echo.Context) error {
	var req acmeclient.Project

	if err := helper.Bind(c, &req); err != nil {
		return err
	}

	proj, err := s.manager.CreateProject(c.Request().Context(), req.Name)
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
		ACMEEndpoint: s.acmeURL(proj.ID),
		CreatedAt:    proj.CreatedAt,
	})
}
