package acme

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"

	"scas/acme/store"
	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/pkg/helper"
)

func (s *Server) createTerm(c echo.Context) error {
	var req acmeclient.Term
	if err := helper.Bind(c, &req); err != nil {
		return err
	}

	cc := c.(*Context)
	term, err := s.manager.CreateTerm(c.Request().Context(), cc.project.ID, &req)
	if err != nil {
		return errors.Wrapf(err, "fail to create term")
	}

	return c.JSON(http.StatusCreated, term)
}

func (s *Server) updateTerm(c echo.Context) error {
	var in acmeclient.Term
	if err := helper.Bind(c, &in); err != nil {
		return err
	}

	if c.Param("term_id") != in.ID {
		return echo.ErrBadRequest
	}

	cc := c.(*Context)
	term, err := s.manager.UpdateTerm(c.Request().Context(), cc.project.ID, &in)
	if err != nil {
		return errors.Wrapf(err, "fail to updated term")
	}

	return c.JSON(http.StatusOK, termToResource(cc.project, term))
}

func termToResource(proj *store.Project, in *store.Term) *acmeclient.Term {
	return &acmeclient.Term{
		ID:        in.ID,
		Content:   in.Content,
		Active:    proj.TermID == in.ID,
		CreatedAt: common.NewTimestamp(in.CreatedAt),
		UpdatedAt: common.NewTimestamp(in.UpdatedAt),
	}
}

func (s *Server) getTerm(c echo.Context) error {
	termID := c.Param("term_id")
	cc := c.(*Context)

	if termID == "" {
		termID = cc.project.TermID
	}

	if termID == "" {
		return echo.ErrNotFound
	}

	term, err := s.manager.GetTerm(c.Request().Context(), cc.project.ID, termID)
	if err != nil {
		return errors.Wrapf(err, "fail to get term")
	}

	return c.JSON(http.StatusOK, termToResource(cc.project, term))
}
