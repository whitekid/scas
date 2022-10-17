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

	// extracted information from path parameters
	project       *types.Project
	ca            *types.CertificateAuthority
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

	certificateID := helper.ExtractParam("certificate_id", func(c echo.Context, val string) { c.(*Context).certificateID = val })

	e.Use(customContext(), app.extractProjectID(), app.extractCAID())

	e.POST("/", app.createProject)
	e.GET("/", app.listProject)
	e.GET("/:project_id", app.getProject)

	e.POST("/:project_id/ca", app.createCA)
	e.GET("/:project_id/ca/:ca_id", app.getCA)
	e.GET("/:project_id/crl", app.getCRL)

	e.POST("/:project_id/certificates", app.createCertificate)
	e.GET("/:project_id/certificates", app.listCertificate)
	e.GET("/:project_id/certificates/:certificate_id", app.getCertificate, certificateID)

	e.POST("/:project_id/certificates/:certificate_id/renewal", app.renewCertificate, certificateID)
	e.POST("/:project_id/certificates/:certificate_id/revoke", app.revokeCertificate, certificateID)
}

func (app *v1Alpha1API) extractProjectID() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			projID := c.Param("project_id")
			if projID == "" {
				c.(*Context).project = &types.Project{}
			} else {
				proj, err := app.repository.GetProject(c.Request().Context(), projID)
				if err != nil {
					return err
				}

				c.(*Context).project = proj
			}

			return next(c)
		}
	}
}

func (app *v1Alpha1API) extractCAID() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cc := c.(*Context)
			caID := c.Param("ca_id")
			if caID == "" {
				cc.ca = &types.CertificateAuthority{}
			} else {
				ca, err := app.repository.GetCertificateAuthority(c.Request().Context(), cc.project.ID, caID)
				if err != nil {
					return err
				}

				cc.ca = ca
			}

			return next(c)
		}
	}
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

	proj, err := app.repository.CreateProject(c.Request().Context(), req.Name)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusCreated, proj)
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

	if cc.project.ID == "" {
		return echo.ErrNotFound
	}

	return c.JSON(http.StatusOK, cc.project)
}

func (app *v1Alpha1API) createCA(c echo.Context) error {
	var in CertificateRequest

	if err := helper.Bind(c, &in); err != nil {
		return err
	}

	cc := c.(*Context)

	log.Debugf("createCA: req=%+v", in)
	req := &certmanager.CreateRequest{
		CommonName:         in.CommonName,
		Hosts:              in.Hosts,
		Country:            in.Country,
		Organization:       in.Organization,
		OrganizationalUnit: in.OrganizationalUnit,
		Locality:           in.Locality,
		Province:           in.Province,
		StreetAddress:      in.StreetAddress,
		PostalCode:         in.PostalCode,
		KeyAlgorithm:       in.KeyAlgorithm,
		IsCA:               true,
		KeyUsage:           in.KeyUsage,
		ExtKeyUsage:        in.ExtKeyUsage,
		NotBefore:          in.NotBefore,
		NotAfter:           in.NotAfter,
	}

	goxp.IfThen(len(in.CRL) > 0, func() { req.CRL = []string{in.CRL} })

	ca, err := app.repository.CreateCertificateAuthority(c.Request().Context(), cc.project.ID, req, in.CAID)
	if err != nil {
		return err
	}

	res, err := caToResource(ca)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, res)
}

func (app *v1Alpha1API) getCA(c echo.Context) error {
	cc := c.(*Context)

	if cc.ca.ID == "" {
		return echo.ErrNotFound
	}

	var req certmanager.CreateRequest
	if err := json.Unmarshal([]byte(cc.ca.Request), &req); err != nil {
		return errors.Wrap(err, "fail to get ca")
	}

	res, err := caToResource(cc.ca)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, res)
}

func caToResource(ca *types.CertificateAuthority) (*v1alpha1.CertificateRequest, error) {
	var req certmanager.CreateRequest
	if err := json.Unmarshal([]byte(ca.Request), &req); err != nil {
		return nil, errors.Wrap(err, "fail to get ca")
	}

	return &v1alpha1.CertificateRequest{
		ID:                 ca.ID,
		CAID:               fx.TernaryCF(ca.CAID == nil, func() string { return "" }, func() string { return *ca.CAID }),
		CommonName:         req.CommonName,
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
	}, nil
}

func (app *v1Alpha1API) getCRL(c echo.Context) error {
	cc := c.(*Context)

	crl, err := app.repository.GetCRL(c.Request().Context(), cc.project.ID)
	if err != nil {
		return err
	}

	return c.Blob(http.StatusOK, "application/pkix-crl", crl)
}

func (app *v1Alpha1API) createCertificate(c echo.Context) error {
	var in CertificateRequest

	if err := helper.Bind(c, &in); err != nil {
		return err
	}

	cc := c.(*Context)

	req := &certmanager.CreateRequest{
		SerialNumber:       in.SerialNumber,
		CommonName:         in.CommonName,
		Hosts:              in.Hosts,
		Country:            in.Country,
		Organization:       in.Organization,
		OrganizationalUnit: in.OrganizationalUnit,
		Locality:           in.Locality,
		Province:           in.Province,
		StreetAddress:      in.StreetAddress,
		PostalCode:         in.PostalCode,
		IsCA:               false,
		CRL:                []string{},
		KeyAlgorithm:       in.KeyAlgorithm,
		KeyUsage:           in.KeyUsage,
		ExtKeyUsage:        in.ExtKeyUsage,
		NotAfter:           in.NotAfter,
		NotBefore:          in.NotBefore,
	}

	goxp.IfThen(len(in.CRL) > 0, func() { req.CRL = []string{in.CRL} })

	cert, err := app.repository.CreateCertificate(c.Request().Context(), cc.project.ID, req, in.CAID)
	if err != nil {
		return err
	}

	cc.certificateID = cert.ID
	return app.getCertificate(c)
}

func (app *v1Alpha1API) listCertificate(c echo.Context) error {
	cc := c.(*Context)

	certs, err := app.repository.ListCertificate(c.Request().Context(), cc.project.ID, certmanager.CertificateListOpt{CN: c.Param("cn")})
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

	cert, err := app.repository.GetCertificate(c.Request().Context(), cc.project.ID, cc.certificateID)
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

	newCert, err := app.repository.RenewCertificate(c.Request().Context(), cc.project.ID, cc.certificateID)
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
	revoked, err := app.repository.RevokeCertificate(c.Request().Context(), cc.project.ID, cc.certificateID, req.Reason)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, revoked)
}
