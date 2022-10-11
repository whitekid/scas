package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/log"

	"scas/acme/store"
	acmeclient "scas/client/acme"
	"scas/pkg/helper"
	"scas/pkg/helper/x509x"
)

// JWK account public key
// KID key URL
// returns account, created
func (m *Manager) NewAccount(ctx context.Context, projID string, JWK string, KID string, req *acmeclient.AccountRequest) (*store.Account, bool, error) {
	log.Debugf("newAccount(): Project=%s JWK=%s, KID=%s", projID, JWK, KID)

	if JWK == "" {
		acctID := idFromURI(KID)
		acct, err := m.store.GetAccount(ctx, projID, acctID)
		if err != nil && !errors.Is(err, store.ErrAccountDoesNotExist) {
			return nil, false, err
		}
		return acct, false, nil
	}

	acct, err := m.store.GetAccountByKey(ctx, projID, JWK)
	if err != nil && !errors.Is(err, store.ErrAccountDoesNotExist) {
		return nil, false, err
	}
	alreadyExisting := acct != nil

	if !alreadyExisting {
		if req.OnlyReturnExisting {
			return nil, false, store.ErrAccountDoesNotExist
		}

		acct = &store.Account{
			AccountResource: acmeclient.AccountResource{
				Status:              acmeclient.AccountStatusValid,
				Contact:             req.Contact,
				TermOfServiceAgreed: req.TermOfServiceAgreed,
			},
			ProjectID: projID,
			Key:       JWK,
		}

		if req.TermOfServiceAgreed {
			acct.TermAgreeAt = time.Now().UTC()
		}

		acct, err = m.store.CreateAccount(ctx, acct)
		if err != nil {
			return nil, false, errors.Wrapf(err, "fail to create account")
		}
	} else {
		if err := m.checkAgreeTerm(acct); err != nil {
			return nil, false, err
		}
	}

	return acct, !alreadyExisting, nil
}

func (m *Manager) checkAgreeTerm(account *store.Account) error {
	if m.termUpdatedAt.IsZero() {
		return nil
	}

	if account.TermAgreeAt.IsZero() || account.TermAgreeAt.After(m.termUpdatedAt) {
		return store.ErrTermOfServiceChanged
	}

	return nil
}

func (m *Manager) UpdateAccount(ctx context.Context, projID string, acctID string, contact []string) (*store.Account, error) {
	acct, err := m.store.GetAccount(ctx, projID, acctID)
	if err != nil {
		return nil, err
	}

	if err := m.checkAgreeTerm(acct); err != nil {
		return nil, err
	}

	if acct, err = m.store.UpdateAccountContact(ctx, projID, acctID, contact); err != nil {
		return nil, err
	}

	return acct, nil
}

// VerifySignature verify request signature, if success returns it's account informations with requested KID
func (m *Manager) VerifySignature(ctx context.Context, projID string, key string, kid string, signature string, header string, payload string) (*store.Account, error) {
	log.Debugf("verifySignature(): key=%s, kid=%s, signature=%s, header=%s, payload=%s", key, kid, signature, header, payload)

	var acct *store.Account
	if key == "" && kid != "" {
		account, err := m.store.GetAccount(ctx, projID, idFromURI(kid))
		if err != nil {
			return nil, err
		}

		acct = account
		key = account.Key
	}

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, store.ErrBadPublicKey
	}

	pub, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, store.ErrBadPublicKey
	}

	ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, store.ErrBadPublicKey
	}

	hash := helper.SHA256Sum([]byte(fmt.Sprintf("%s.%s", header, payload)))
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, errors.Wrap(err, "signature decode failed")
	}

	if !x509x.VerifySignature(ecdsaPubKey, hash, sig) {
		return nil, store.ErrBadSignature
	}

	return acct, nil
}

func (m *Manager) UpdateAccountKey(ctx context.Context, projID string, oldKey, newKey string) (*store.Account, error) {
	acct, err := m.store.GetAccountByKey(ctx, projID, oldKey)
	if err != nil {
		return nil, err
	}

	if _, err := m.store.GetAccountByKey(ctx, projID, newKey); err == nil {
		return nil, errors.New("account already exists with the key")
	}

	if _, err := m.store.UpdateAccountKey(ctx, projID, acct.ID, newKey); err != nil {
		return nil, err
	}

	return nil, nil
}

func (m *Manager) DeactivateAccount(ctx context.Context, projID string, acctID string) (*store.Account, error) {
	acct, err := m.store.GetAccount(ctx, projID, acctID)
	if err != nil {
		return nil, err
	}

	if err := m.checkAgreeTerm(acct); err != nil {
		return nil, err
	}

	if acct, err = m.store.UpdateAccountStatus(ctx, projID, acctID, acmeclient.AccountStatusDeactivated); err != nil {
		return nil, err
	}

	return acct, nil
}
