package manager

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"time"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/acme/ca"
	"scas/acme/store"
	acmeclient "scas/client/acme"
	"scas/client/common"
)

const (
	orderTimeout = time.Minute * 30
	authTimeout  = time.Minute * 30
)

func (m *Manager) NewOrder(ctx context.Context, projID string, acctID string, identifiers []common.Identifier, notBefore *common.Timestamp, notAfter *common.Timestamp) (*store.Order, error) {
	log.Debugf("NewOrder(): project=%s, acctID=%s", projID, acctID)

	acct, err := m.store.GetAccount(ctx, projID, acctID)
	if err != nil {
		return nil, err
	}

	order, err := m.store.CreateOrder(ctx, &store.Order{
		Order: &acmeclient.Order{
			OrderResource: acmeclient.OrderResource{
				Status:      acmeclient.OrderStatusPending,
				Expires:     common.TimestampNow().Add(orderTimeout),
				Identifiers: identifiers,
				NotBefore:   notBefore,
				NotAfter:    notAfter,
			},
		},
		ProjectID: projID,
		AccountID: acct.ID,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "fail to create order")
	}

	for _, identifier := range identifiers {
		authz, err := m.store.CreateAuthz(ctx, &store.Authz{
			ProjectID:  projID,
			AccountID:  acct.ID,
			OrderID:    order.ID,
			Status:     acmeclient.AuthzStatusPending,
			Expires:    common.TimestampNow().Add(authTimeout),
			Identifier: identifier,
			Wildcard:   false,
		})
		if err != nil {
			return nil, errors.Wrapf(err, "fail to create authz")
		}
		order.Authz = append(order.Authz, authz.ID)

		_, err = m.store.CreateChallenge(ctx, &store.Challenge{
			Challenge: &acmeclient.Challenge{
				Type:   acmeclient.ChallengeTypeHttp01,
				Status: acmeclient.ChallengeStatusPending,
				Token:  base64.RawURLEncoding.EncodeToString(goxp.RandomByte(40)),
			},
			ProjectID: projID,
			AuthzID:   authz.ID,
		})
		if err != nil {
			return nil, errors.Wrapf(err, "fail to create order")
		}
	}

	return m.store.GetOrder(ctx, order.ID)
}

func (m *Manager) FinalizeOrder(ctx context.Context, orderID string, csr *x509.CertificateRequest) (*store.Order, error) {
	log.Debugf("FinalizeOrder() orderID=%s", orderID)

	order, err := m.store.GetOrder(ctx, orderID)
	if err != nil {
		return nil, err
	}

	if order.Expires.Before(time.Now().UTC()) {
		return nil, store.ErrOrderExpired
	}

	if order.Status != acmeclient.OrderStatusReady {
		return nil, store.ErrOrderNotReady
	}

	// check authorization
	for _, authURI := range order.Authz {
		auth, err := m.store.GetAuthz(ctx, idFromURI(authURI))
		if err != nil {
			return nil, err
		}

		if auth.Status != acmeclient.AuthzStatusValid {
			return nil, store.ErrAuthzNotReady // TODO errUnauthorized
		}
	}

	// check if csr information has same information to order
	// CSR은 order의 정보와 같아아함
	if len(fx.Filter(order.Identifiers, func(x common.Identifier) bool {
		return x.Type == common.IdentifierDNS && (x.Value == csr.Subject.CommonName || fx.Contains(csr.DNSNames, x.Value))
	})) == 0 {
		log.Debugf("bad csr: idetifier: %v, csr.DNSNames=%v", order.Identifiers, csr.DNSNames)
		return nil, store.ErrBadCSR
	}

	// TODO If the account is not authorized for the identifiers indicated in the CSR
	// TODO If the CSR requests extensions that the CA is not willing to include

	serial, ok := big.NewInt(0).SetString(csr.Subject.SerialNumber, 10)
	if !ok {
		log.Errorf("bad csr: invalid serial: serial=%s", csr.Subject.SerialNumber)
		return nil, store.ErrBadCSR
	}

	proj, err := m.store.GetProject(ctx, order.ProjectID)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to finalize certificate")
	}

	caGen := ca.NewLocal()
	// TODO private key를 어디선가 써야하겠지?
	certPEM, _, chainPEM, err := caGen.CreateCertificate(ctx, &ca.CreateRequest{
		SerialNumber: serial,
		Subject:      csr.Subject,
		Issuer: pkix.Name{
			CommonName:         proj.CommonName,
			Country:            []string{proj.Country},
			Organization:       []string{proj.Organization},
			OrganizationalUnit: []string{proj.OrganizationalUnit},
			Locality:           []string{proj.Locality},
			Province:           []string{proj.Province},
			StreetAddress:      []string{proj.StreetAddress},
			PostalCode:         []string{proj.PostalCode},
		},
		DNSNames:       csr.DNSNames,
		EmailAddresses: csr.EmailAddresses,
		IPAddresses:    csr.IPAddresses,
		URIs:           csr.URIs,
		NotBefore:      order.NotBefore.Time,
		NotAfter:       order.NotAfter.Time,
		KeyUsage:       proj.KeyUsage,
		ExtKeyUsage:    proj.ExtKeyUsage,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "fail to create certificate")
	}

	log.Debugf("@@@@ cert: %s", certPEM)
	_, err = m.store.CreateCertificate(ctx, &store.Certificate{
		ProjectID: order.ProjectID,
		OrderID:   order.ID,
		Chain:     append(certPEM, chainPEM...),
	})
	if err != nil {
		return nil, errors.Wrap(err, "certificate create failed")
	}

	order, err = m.store.UpdateOrderStatus(ctx, order.ID, acmeclient.OrderStatusValid)
	if err != nil {
		return nil, errors.Wrap(err, "finalize order failed")
	}

	return order, nil
}

func (m *Manager) Authorize(ctx context.Context, authzID string) (*store.Authz, error) {
	authz, err := m.store.GetAuthz(ctx, authzID)
	if err != nil {
		return nil, err
	}

	return authz, nil
}
