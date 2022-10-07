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
				Expires:     common.TimestampNow().Add(orderTimeout), // TODO check order expires periodically
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
		order.Status = acmeclient.OrderStatusReady
		return nil, store.ErrBadCSR
	}

	// TODO generate key with CA 현재는 self-signed임...
	// 조금 복잡하군... CA라면 parent CA등과 연계가 필요하고... local CA도 마찬가지인데..
	// 이건 project, acme pool 등과 연계가 되어야할 것 같음...
	privateKey, err := x509x.GenerateKey(csr.SignatureAlgorithm)
	if err != nil {
		return nil, errors.Wrapf(err, "key generate failed")
	}
	parentPrivateKey := privateKey

	template := &x509.Certificate{
		SerialNumber:    x509x.RandomSerial(),
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
		ProjectID: order.ProjectID,
		OrderID:   order.ID,
		Chain:     x509x.EncodeCertificateToPEM(cert),
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
