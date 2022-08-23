package manager

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	"scas/acme/store"
	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/pkg/helper/x509x"
)

const (
	orderTimeout = time.Minute * 30
	authTimeout  = time.Minute * 30
)

func (m *Manager) NewOrder(ctx context.Context, kid string, identifiers []common.Identifier, notBefore *common.Timestamp, notAfter *common.Timestamp) (*store.Order, error) {
	log.Debugf("NewOrder(): kid=%s", kid)

	acct, err := m.store.GetAccount(ctx, idFromURI(kid))
	if err != nil {
		return nil, err
	}

	order, err := m.store.CreateOrder(ctx, &store.Order{
		Order: &acmeclient.Order{
			OrderResource: acmeclient.OrderResource{
				Status:      acmeclient.OrderStatusPending,
				Expires:     common.TimestampNow().Add(orderTimeout), // TODO check order expires periodically
				Identifiers: identifiers,
				NotBefore:   notBefore,
				NotAfter:    notAfter,
			},
		},
		AccountID: acct.ID,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "fail to create order")
	}

	for _, identifier := range identifiers {
		authz, err := m.store.CreateAuthz(ctx, &store.Authz{
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
				Type:   acmeclient.ChallengeHTTP01,
				Status: acmeclient.ChallengeStatusPending,
				Token:  base64.RawURLEncoding.EncodeToString(goxp.RandomByte(40)),
			},
			AuthzID: authz.ID,
		})
		if err != nil {
			return nil, errors.Wrapf(err, "fail to create order")
		}
	}

	return m.store.GetOrder(ctx, order.ID)
}

func (m *Manager) FinalizeOrder(ctx context.Context, orderID string, csr *x509.CertificateRequest) (*store.Order, error) {
	log.Debugf("finalizeOrder() orderID=%s", orderID)

	order, err := m.store.GetOrder(ctx, orderID)
	if err != nil {
		return nil, err
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

	if len(fx.Filter(order.Identifiers, func(x common.Identifier) bool {
		return x.Type == common.IdentifierDNS && (x.Value == csr.Subject.CommonName || fx.Contains(csr.DNSNames, x.Value))
	})) == 0 {
		order.Status = acmeclient.OrderStatusReady // TODO 응?... ready 상태로 두라고?? 7.4
		return nil, store.ErrOrderNotReady
	}

	// TODO generate key with CA
	privateKey, err := x509x.GenerateKey(x509.ECDSAWithSHA256)
	if err != nil {
		return nil, errors.Wrapf(err, "key generate failed")
	}
	parentPrivateKey := privateKey

	template := &x509.Certificate{
		SerialNumber:    x509x.RandSerial(),
		Subject:         csr.Subject,
		Extensions:      csr.Extensions,
		ExtraExtensions: csr.ExtraExtensions,
		DNSNames:        csr.DNSNames,
		EmailAddresses:  csr.EmailAddresses,
		IPAddresses:     csr.IPAddresses,
		URIs:            csr.URIs,
		NotBefore:       order.NotBefore.Time,
		NotAfter:        order.NotAfter.Time,
	}
	parent := template
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, privateKey.Public(), parentPrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "certificate create failed")
	}

	// TODO with chain
	_, err = m.store.CreateCertificate(ctx, &store.Certificate{
		OrderID: order.ID,
		Chain:   x509x.EncodeCertificateToPEM(cert),
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

func (m *Manager) GetCertificate(ctx context.Context, certID string) (*store.Certificate, error) {
	cert, err := m.store.GetCertificate(ctx, certID)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
