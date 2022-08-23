package manager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/whitekid/goxp/log"

	"scas/acme/store"
	acmeclient "scas/client/acme"
	"scas/pkg/helper/x509x"
)

// JWK account public key
// KID key URL
// returns account, created
func (m *Manager) NewAccount(ctx context.Context, JWK string, KID string, req *acmeclient.AccountRequest) (*store.Account, bool, error) {
	log.Debugf("newAccount(): JWK=%s, KID=%s", JWK, KID)

	if JWK == "" {
		acctID := idFromURI(KID)
		acct, err := m.store.GetAccount(ctx, acctID)
		if err != nil && !errors.Is(err, store.ErrAccountDoesNotExist) {
			return nil, false, err
		}
		return acct, false, nil
	}

	acct, err := m.store.GetAccountByKey(ctx, JWK)
	if err != nil && !errors.Is(err, store.ErrAccountDoesNotExist) {
		return nil, false, err
	}
	alreadyExisting := acct != nil

	if !alreadyExisting {
		if req.OnlyReturnExisting {
			return nil, false, store.ErrAccountDoesNotExist
		}

		// TODO agree term; directory에 term 정보가 있어야함.
		// 사용자가 aggree한 이후에 변경된 term에 대해서 ...

		acct = &store.Account{
			AccountResource: acmeclient.AccountResource{
				Status:              acmeclient.AccountStatusValid,
				Contact:             req.Contact,
				TermOfServiceAgreed: req.TermOfServiceAgreed,
			},
			Key: JWK,
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

func (m *Manager) UpdateAccount(ctx context.Context, acctID string, contact []string) (*store.Account, error) {
	acct, err := m.store.GetAccount(ctx, acctID)
	if err != nil {
		return nil, err
	}

	if err := m.checkAgreeTerm(acct); err != nil {
		return nil, err
	}

	if acct, err = m.store.UpdateAccountContact(ctx, acctID, contact); err != nil {
		return nil, err
	}

	return acct, nil
}

func (m *Manager) VerifySignature(ctx context.Context, key string, kid string, signature string, header string, payload string) error {
	log.Debugf("verifySignature(): key=%s, kid=%s, signature=%s, header=%s, payload=%s", key, kid, signature, header, payload)

	if key == "" && kid != "" {
		account, err := m.store.GetAccount(ctx, idFromURI(kid))
		if err != nil {
			return err
		}

		key = account.Key
	}

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return store.ErrBadPublicKey
	}

	pub, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return store.ErrBadPublicKey
	}

	ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return store.ErrBadPublicKey
	}

	hash := crypto.SHA256.New().Sum([]byte(fmt.Sprintf("%s.%s", header, payload)))
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return errors.Wrap(err, "signature decode failed")
	}

	if !x509x.VerifySignature(ecdsaPubKey, hash, sig) {
		return store.ErrBadSignature
	}

	return nil
}

func (m *Manager) UpdateAccountKey(ctx context.Context, oldKey, newKey string) (*store.Account, error) {
	acct, err := m.store.GetAccountByKey(ctx, oldKey)
	if err != nil {
		return nil, err
	}

	if _, err := m.store.GetAccountByKey(ctx, newKey); err == nil {
		return nil, errors.New("account already exists with the key")
	}

	if _, err := m.store.UpdateAccountKey(ctx, acct.ID, newKey); err != nil {
		return nil, err
	}

	return nil, nil
}
