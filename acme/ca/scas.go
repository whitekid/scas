package ca

import (
	"context"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/log"

	"scas/client/v1alpha1"
)

func NewSCAS(endpoint string, projectID string, CAID string) Interface {
	return &scasImpl{
		client: v1alpha1.New(endpoint),
		projID: projectID,
		caID:   CAID,
	}
}

type scasImpl struct {
	client *v1alpha1.Client // SCAS CA Client
	projID string
	caID   string
}

var _ Interface = (*scasImpl)(nil)

func (s *scasImpl) CreateCertificate(ctx context.Context, in *CreateRequest) ([]byte, []byte, []byte, error) {
	log.Debugf("CreateCertificate(): proj=%s, ca=%s, req=%+v", s.projID, s.caID, in)

	cert, err := s.client.Projects(s.projID).Certificates().Create(ctx, &v1alpha1.CertificateRequest{
		SerialNumber:       in.SerialNumber,
		CAID:               s.caID,
		CommonName:         in.Subject.CommonName,
		Country:            in.Subject.Country,
		Province:           in.Subject.Province,
		Locality:           in.Subject.Locality,
		StreetAddress:      in.Subject.StreetAddress,
		PostalCode:         in.Subject.PostalCode,
		Organization:       in.Subject.Organization,
		OrganizationalUnit: in.Subject.OrganizationalUnit,
		Hosts:              in.Hosts,
		KeyAlgorithm:       in.KeyAlgorithm,
		KeyUsage:           in.KeyUsage,
		ExtKeyUsage:        in.ExtKeyUsage,
		NotAfter:           in.NotAfter,
		NotBefore:          in.NotBefore,
		// CRL:          "", // TODO
	})
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "fail to create certificate")
	}

	return cert.TlsCrtPEM, cert.TlsKeyPEM, cert.ChainCrtPEM, nil
}
