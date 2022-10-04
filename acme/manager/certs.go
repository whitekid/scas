package manager

import (
	"context"
	"encoding/hex"

	"github.com/whitekid/goxp/log"

	"scas/acme/store"
	"scas/client/common/x509types"
	"scas/pkg/helper"
)

func (m *Manager) GetCertificate(ctx context.Context, certID string) (*store.Certificate, error) {
	log.Debugf("GetCertificate()")

	cert, err := m.store.GetCertificate(ctx, certID)
	if err != nil {
		return nil, err
	}

	if cert.RevokedAt != nil {
		return nil, store.ErrAlreadyRevoked
	}

	return cert, nil
}

// RevokeCertificate revoke certificate
// cert PEM format certificate
func (m *Manager) RevokeCertificate(ctx context.Context, certPEM []byte, reason x509types.RevokeReason) error {
	log.Debugf("RevokeCertificate()")

	if reason.String() == "" {
		return store.ErrBadRevocationReason
	}

	cert, err := m.store.GetCertificateBySum(ctx, hex.EncodeToString(helper.SHA256Sum(certPEM)))
	if err != nil {
		return err
	}

	if cert.RevokedAt != nil {
		return store.ErrAlreadyRevoked
	}

	if _, err := m.store.RevokeCertificate(ctx, cert.ID, reason); err != nil {
		return err
	}

	return nil
}
