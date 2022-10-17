package ca

import (
	"context"
	"net"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/fx"
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
		Country:            fx.TernaryCF(len(in.Subject.Country) > 0, func() string { return in.Subject.Country[0] }, func() string { return "" }),
		Province:           fx.TernaryCF(len(in.Subject.Province) > 0, func() string { return in.Subject.Province[0] }, func() string { return "" }),
		Locality:           fx.TernaryCF(len(in.Subject.Locality) > 0, func() string { return in.Subject.Locality[0] }, func() string { return "" }),
		StreetAddress:      fx.TernaryCF(len(in.Subject.StreetAddress) > 0, func() string { return in.Subject.StreetAddress[0] }, func() string { return "" }),
		PostalCode:         fx.TernaryCF(len(in.Subject.PostalCode) > 0, func() string { return in.Subject.PostalCode[0] }, func() string { return "" }),
		Organization:       fx.TernaryCF(len(in.Subject.Organization) > 0, func() string { return in.Subject.Organization[0] }, func() string { return "" }),
		OrganizationalUnit: fx.TernaryCF(len(in.Subject.OrganizationalUnit) > 0, func() string { return in.Subject.OrganizationalUnit[0] }, func() string { return "" }),
		Hosts:              append(append(in.DNSNames, in.EmailAddresses...), fx.Map(in.IPAddresses, func(ip net.IP) string { return ip.String() })...),
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
