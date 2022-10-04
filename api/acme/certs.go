package acme

import (
	"encoding/base64"
	"encoding/pem"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"

	"scas/acme/store"
	acmeclient "scas/client/acme"
	"scas/client/common/x509types"
	"scas/pkg/helper/x509x"
)

// getCert download certificate
func (s *ACMEServer) getCert(c echo.Context) error {
	cert, err := s.manager.GetCertificate(c.Request().Context(), c.Param("cert_id"))
	if err != nil {
		return errors.Wrap(err, "fail to get certificate")
	}

	c.Response().Header().Set(echo.HeaderContentType, "application/pem-certificate-chain")
	c.Response().WriteHeader(http.StatusOK)

	c.Response().Writer.Write(cert.Chain)
	c.Response().Flush()

	return nil
}

func (s *ACMEServer) revokeCert(c echo.Context) error {
	var req acmeclient.CertificateRevoke
	if err := s.parseJOSEPayload(c, &req); err != nil {
		return err
	}

	certDER, err := base64.RawURLEncoding.DecodeString(req.Certificate)
	if err != nil {
		return errors.Wrapf(store.ErrMalformed, err.Error())
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    x509x.CertificatePEMBlockType,
		Headers: nil,
		Bytes:   certDER,
	})

	if err := s.manager.RevokeCertificate(c.Request().Context(), pemBytes, x509types.RevokeReason(req.Reason)); err != nil {
		return err
	}

	return nil
}
