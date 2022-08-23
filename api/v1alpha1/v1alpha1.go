package v1alpha1

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/whitekid/goxp"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/api/endpoints"
	"scas/certmanager"
	"scas/certmanager/types"
	"scas/client/common"
	"scas/client/v1alpha1"
	"scas/pkg/helper"
)

// @title    SCAS
// @version  v1alpha1
// @BasePath /v1alpha1
type v1Alpha1API struct {
	repository certmanager.Interface
}

func init() {
	endpoints.Register(New())
}

func New() *v1Alpha1API {
	// TODO configure DBUrl
	return NewWithRepository(certmanager.New(certmanager.NativeProvider(), certmanager.SQLStore("sqlite://test.db")))
}

func NewWithRepository(repo certmanager.Interface) *v1Alpha1API {
	return &v1Alpha1API{
		repository: repo,
	}
}

var _ endpoints.Endpoint = (*v1Alpha1API)(nil)

func (app *v1Alpha1API) PathAndName() (string, string) { return "/v1alpha1", "v1alpha1 handler" }

type Context struct {
	echo.Context

	// path parameters
	projectID     string
	caPoolID      string
	caID          string
	certificateID string
}

func customContext() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cc, ok := c.(*Context)
			if !ok {
				cc = &Context{Context: c}
			}

			return next(cc)
		}
	}
}

func (app *v1Alpha1API) Route(e *echo.Group) {
	e.Use(handleError)

	projectID := helper.ExtractParam("project_id", func(c echo.Context, val string) { c.(*Context).projectID = val })
	caPoolID := helper.ExtractParam("capool", func(c echo.Context, val string) { c.(*Context).caPoolID = val })
	caID := helper.ExtractParam("ca_id", func(c echo.Context, val string) { c.(*Context).caID = val })
	certificateID := helper.ExtractParam("certificate_id", func(c echo.Context, val string) { c.(*Context).certificateID = val })

	e.Use(customContext())
	e.Use(projectID)

	e.POST("/", app.createProject)
	e.GET("/", app.listProject)
	e.GET("/:project_id", app.getProject, projectID)

	e.POST("/:project_id/capools", app.createCAPool)
	e.GET("/:project_id/capools", app.listCAPool)
	e.GET("/:project_id/capools/:capool", app.getCAPool, caPoolID)

	e.POST("/:project_id/capools/:capool/ca", app.createCA, caPoolID)
	e.GET("/:project_id/capools/:capool/ca/:ca_id", app.getCA, caPoolID, caID)
	e.GET("/:project_id/capools/:capool/crl", app.getCRL, caPoolID)

	e.POST("/:project_id/capools/:capool/certificates", app.createCertificate, caPoolID)
	e.GET("/:project_id/capools/:capool/certificates", app.listCertificate, caPoolID)
	e.GET("/:project_id/capools/:capool/certificates/:certificate_id", app.getCertificate, caPoolID, certificateID)

	e.POST("/:project_id/capools/:capool/certificates/:certificate_id/renewal", app.renewCertificate, caPoolID, certificateID)
	e.POST("/:project_id/capools/:capool/certificates/:certificate_id/revoke", app.revokeCertificate, caPoolID, certificateID)
}

func handleError(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		err := next(c)
		if err == nil {
			return err
		}

		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}

		code := http.StatusInternalServerError

		switch {
		case errors.Is(err, certmanager.ErrRecordNotFound):
			code = http.StatusNotFound
		case errors.Is(err, certmanager.ErrUniqueConstraintFailed):
			code = http.StatusConflict
		case errors.Is(err, certmanager.ErrForeignKeyConstraintFailed):
			code = http.StatusBadRequest
		case helper.IsValidationError(err):
			code = http.StatusBadRequest
		default:
			log.Debugf("unhandled err=%T %t, %v", err, err, err)
		}

		if code > 0 {
			err = echo.NewHTTPError(code, err.Error())
		}

		return err
	}
}

func (app *v1Alpha1API) createProject(c echo.Context) error {
	var req Project

	if err := helper.Bind(c, &req); err != nil {
		return err
	}

	cc := c.(*Context)

	capool, err := app.repository.CreateProject(c.Request().Context(), cc.projectID)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusCreated, capool)
}

func (app *v1Alpha1API) listProject(c echo.Context) error {
	items, err := app.repository.ListProject(c.Request().Context(), certmanager.ProjectListOpt{})
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, &v1alpha1.ProjectList{
		Items: fx.Map(items, func(project *types.Project) *v1alpha1.Project {
			return &v1alpha1.Project{
				ID:      project.ID,
				Name:    project.Name,
				Created: common.NewTimestamp(project.Created),
			}
		}),
	})
}

func (app *v1Alpha1API) getProject(c echo.Context) error {
	cc := c.(*Context)

	project, err := app.repository.GetProject(c.Request().Context(), cc.projectID)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, project)
}

func (app *v1Alpha1API) createCAPool(c echo.Context) error {
	var req CAPool

	if err := helper.Bind(c, &req); err != nil {
		return err
	}

	cc := c.(*Context)

	capool, err := app.repository.CreateCAPool(c.Request().Context(), cc.projectID, req.Name)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusCreated, capool)
}

func (app *v1Alpha1API) listCAPool(c echo.Context) error {
	cc := c.(*Context)

	items, err := app.repository.ListCAPool(c.Request().Context(), cc.projectID, certmanager.CAPoolListOpt{})
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, &v1alpha1.CAPoolList{
		Items: fx.Map(items, func(pool *types.CAPool) *v1alpha1.CAPool {
			return &v1alpha1.CAPool{
				ID:      pool.ID,
				Name:    pool.Name,
				Created: common.NewTimestamp(pool.Created),
			}
		}),
	})
}

func (app *v1Alpha1API) getCAPool(c echo.Context) error {
	cc := c.(*Context)

	caPool, err := app.repository.GetCAPool(c.Request().Context(), cc.projectID, cc.caPoolID)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, caPool)
}

func (app *v1Alpha1API) createCA(c echo.Context) error {
	var req CertificateRequest

	if err := helper.Bind(c, &req); err != nil {
		return err
	}

	cc := c.(*Context)

	log.Debugf("createCA: req=%+v", req)
	creq := &certmanager.CreateRequest{
		CommonName:         req.CN,
		Hosts:              req.Hosts,
		Country:            req.Country,
		Organization:       req.Organization,
		OrganizationalUnit: req.OrganizationalUnit,
		Locality:           req.Locality,
		Province:           req.Province,
		StreetAddress:      req.StreetAddress,
		PostalCode:         req.PostalCode,
		KeyAlgorithm:       req.KeyAlgorithm,
		IsCA:               true,
		KeyUsage:           req.KeyUsage,
		ExtKeyUsage:        req.ExtKeyUsage,
		NotBefore:          req.NotBefore,
		NotAfter:           req.NotAfter,
	}

	goxp.IfThen(len(req.CRL) > 0, func() { creq.CRL = []string{req.CRL} })

	ca, err := app.repository.CreateCertificateAuthority(c.Request().Context(), cc.projectID, cc.caPoolID, creq, req.CAID)
	if err != nil {
		return err
	}

	cc.caID = ca.ID
	return app.getCA(c)
}

func (app *v1Alpha1API) getCA(c echo.Context) error {
	cc := c.(*Context)

	ca, err := app.repository.GetCertificateAuthority(c.Request().Context(), cc.projectID, cc.caPoolID, cc.caID)
	if err != nil {
		return errors.Wrap(err, "fail to get ca")
	}

	var req certmanager.CreateRequest
	if err := json.Unmarshal([]byte(ca.Request), &req); err != nil {
		return errors.Wrap(err, "fail to get ca")
	}

	return c.JSON(http.StatusOK, &v1alpha1.CertificateRequest{
		ID:                 ca.ID,
		CAID:               fx.TernaryCF(ca.CAID == nil, func() string { return "" }, func() string { return *ca.CAID }),
		CN:                 req.CommonName,
		Country:            req.Country,
		Province:           req.Province,
		Locality:           req.Locality,
		StreetAddress:      req.StreetAddress,
		PostalCode:         req.PostalCode,
		Organization:       req.Organization,
		OrganizationalUnit: req.OrganizationalUnit,
		Hosts:              req.Hosts,
		KeyAlgorithm:       req.KeyAlgorithm,
		KeyUsage:           req.KeyUsage,
		ExtKeyUsage:        req.ExtKeyUsage,
		NotAfter:           req.NotAfter,
		NotBefore:          req.NotBefore,
		CRL:                fx.TernaryCF(len(req.CRL) > 0, func() string { return req.CRL[0] }, func() string { return "" }),
	})
}

func (app *v1Alpha1API) getCRL(c echo.Context) error {
	cc := c.(*Context)

	crl, err := app.repository.GetCRL(c.Request().Context(), cc.projectID, cc.caPoolID)
	if err != nil {
		return err
	}

	return c.Blob(http.StatusOK, "application/pkix-crl", crl)
}

func (app *v1Alpha1API) createCertificate(c echo.Context) error {
	var req CertificateRequest

	if err := helper.Bind(c, &req); err != nil {
		return err
	}

	cc := c.(*Context)

	creq := &certmanager.CreateRequest{
		CommonName:         req.CN,
		Hosts:              req.Hosts,
		Country:            req.Country,
		Organization:       req.Organization,
		OrganizationalUnit: req.OrganizationalUnit,
		Locality:           req.Locality,
		Province:           req.Province,
		StreetAddress:      req.StreetAddress,
		PostalCode:         req.PostalCode,
		IsCA:               false,
		CRL:                []string{},
		KeyAlgorithm:       req.KeyAlgorithm,
		KeyUsage:           req.KeyUsage,
		ExtKeyUsage:        req.ExtKeyUsage,
		NotAfter:           req.NotAfter,
		NotBefore:          req.NotBefore,
	}

	goxp.IfThen(len(req.CRL) > 0, func() { creq.CRL = []string{req.CRL} })

	cert, err := app.repository.CreateCertificate(c.Request().Context(), cc.projectID, cc.caPoolID, creq, req.CAID)
	if err != nil {
		return err
	}

	cc.certificateID = cert.ID
	return app.getCertificate(c)
}

func (app *v1Alpha1API) listCertificate(c echo.Context) error {
	cc := c.(*Context)

	certs, err := app.repository.ListCertificate(c.Request().Context(), cc.projectID, cc.caPoolID, certmanager.CertificateListOpt{CN: c.Param("cn")})
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, &v1alpha1.CertificateList{
		Items: fx.Map(certs, func(cert *types.Certificate) *v1alpha1.Certificate {
			return &v1alpha1.Certificate{
				ID:          cert.ID,
				Status:      cert.Status,
				CAID:        cert.CAID,
				TlsCrtPEM:   cert.Cert,
				TlsKeyPEM:   cert.Key,
				ChainCrtPEM: cert.Chain,
			}
		}),
	})
}

func (app *v1Alpha1API) getCertificate(c echo.Context) error {
	cc := c.(*Context)

	cert, err := app.repository.GetCertificate(c.Request().Context(), cc.projectID, cc.caPoolID, cc.certificateID)
	if err != nil {
		return err
	}

	req := &v1alpha1.Certificate{
		ID:          cert.ID,
		Status:      cert.Status,
		CAID:        cert.CAID,
		TlsCrtPEM:   cert.Cert,
		TlsKeyPEM:   cert.Key,
		ChainCrtPEM: cert.Chain,
	}

	return c.JSON(http.StatusOK, req)
}

func (app *v1Alpha1API) renewCertificate(c echo.Context) error {
	cc := c.(*Context)

	newCert, err := app.repository.RenewCertificate(c.Request().Context(), cc.projectID, cc.caPoolID, cc.certificateID)
	if err != nil {
		return err
	}

	cc.certificateID = newCert.ID
	return app.getCertificate(c)
}

func (app *v1Alpha1API) revokeCertificate(c echo.Context) error {
	req := new(v1alpha1.RevokeRequest)

	if err := helper.Bind(c, req); err != nil {
		return err
	}

	cc := c.(*Context)
	revoked, err := app.repository.RevokeCertificate(c.Request().Context(), cc.projectID, cc.caPoolID, cc.certificateID, req.Reason)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, revoked)
}
