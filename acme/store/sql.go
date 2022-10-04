package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/lithammer/shortuuid/v4"
	"github.com/pkg/errors"
	"github.com/whitekid/goxp"
	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"scas/acme/store/models"
	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/client/common/x509types"
	"scas/pkg/helper"
	"scas/pkg/helper/gormx"
)

type sqlStoreImpl struct {
	db *gorm.DB
}

func NewSQLStore(dburl string) Interface {
	db, err := gormx.Open(dburl, &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix: "acme_",
		},
	})
	if err != nil {
		panic(err)
	}

	if err := models.Migrate(db); err != nil {
		panic(err)
	}

	return &sqlStoreImpl{db: db}
}

func (s *sqlStoreImpl) CreateNonce(ctx context.Context) (string, error) {
	ID := shortuuid.New()

	nonce := &models.Nonce{
		ID:     ID,
		Expire: time.Now().UTC().Add(nonceTimeout),
	}

	if tx := s.db.WithContext(ctx).Create(nonce); tx.Error != nil {
		return "", gormx.ConvertSQLError(tx.Error)
	}

	return nonce.ID, nil
}

func (s *sqlStoreImpl) ValidNonce(ctx context.Context, nonce string) bool {
	var n models.Nonce
	if tx := s.db.WithContext(ctx).First(&n, "id = ?", nonce); tx.Error != nil {
		return false
	}

	return n.Expire.After(time.Now().UTC())
}

func (s *sqlStoreImpl) CleanupExpiredNonce(ctx context.Context) error {
	return s.db.WithContext(ctx).Where("expire < ?", time.Now().UTC()).Delete(&models.Nonce{}).Error
}

func (s *sqlStoreImpl) CreateAccount(ctx context.Context, acct *Account) (*Account, error) {
	if err := helper.ValidateStruct(acct); err != nil {
		return nil, err
	}

	acctRef := &models.Account{
		ID:                  shortuuid.New(),
		Key:                 acct.Key,
		TermAgreeAt:         &acct.TermAgreeAt,
		Status:              acct.Status.String(),
		Contacts:            strings.Join(acct.Contact, ","),
		TermOfServiceAgreed: acct.TermOfServiceAgreed,
	}

	if tx := s.db.WithContext(ctx).Create(acctRef); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return modelsToAccount(acctRef), nil
}

func modelsToAccount(acct *models.Account) *Account {
	return &Account{
		AccountResource: acmeclient.AccountResource{
			Status:              acmeclient.AccountStatus(acct.Status),
			Contact:             fx.Ternary(len(acct.Contacts) > 0, strings.Split(acct.Contacts, ","), nil),
			TermOfServiceAgreed: acct.TermOfServiceAgreed,
		},
		ID:          acct.ID,
		Key:         acct.Key,
		TermAgreeAt: *acct.TermAgreeAt,
	}
}

type ListAccountOpts struct {
	ID  string
	Key string
}

func (s *sqlStoreImpl) ListAccount(ctx context.Context, opts ListAccountOpts) ([]*Account, error) {
	accts, err := s.listAccount(ctx, opts)
	if err != nil {
		return nil, err
	}

	return fx.Map(accts, func(acct *models.Account) *Account { return modelsToAccount(acct) }), nil
}

func (s *sqlStoreImpl) listAccount(ctx context.Context, opts ListAccountOpts) ([]*models.Account, error) {
	w := &models.Account{
		ID:  opts.ID,
		Key: opts.Key,
	}

	var accts []*models.Account
	if tx := s.db.WithContext(ctx).Order("created_at").Find(&accts, w); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return accts, nil
}

func (s *sqlStoreImpl) GetAccount(ctx context.Context, acctID string) (*Account, error) {
	acct, err := s.getAccount(ctx, acctID)
	if err != nil {
		return nil, err
	}

	return modelsToAccount(acct), nil
}

func (s *sqlStoreImpl) getAccount(ctx context.Context, acctID string) (*models.Account, error) {
	accts, err := s.listAccount(ctx, ListAccountOpts{
		ID: acctID,
	})
	if err != nil {
		return nil, err
	}

	switch len(accts) {
	case 0:
		return nil, ErrAccountDoesNotExist
	case 1:
		return accts[0], nil
	default:
		return nil, ErrMultipleRecords
	}
}

func (s *sqlStoreImpl) GetAccountByKey(ctx context.Context, key string) (*Account, error) {
	accts, err := s.ListAccount(ctx, ListAccountOpts{
		Key: key,
	})
	if err != nil {
		return nil, err
	}

	switch len(accts) {
	case 0:
		return nil, ErrAccountDoesNotExist
	case 1:
		return accts[0], nil
	default:
		return nil, ErrMultipleRecords
	}
}

func (s *sqlStoreImpl) updateAccount(ctx context.Context, acctID string, fn func(acct *models.Account) error) (*Account, error) {
	acct, err := s.getAccount(ctx, acctID)
	if err != nil {
		return nil, err
	}

	if err := fn(acct); err != nil {
		return nil, err
	}

	if tx := s.db.Save(acct); tx.Error != nil {
		return nil, tx.Error
	}

	return modelsToAccount(acct), nil
}

func (s *sqlStoreImpl) UpdateAccountContact(ctx context.Context, acctID string, contacts []string) (*Account, error) {
	return s.updateAccount(ctx, acctID, func(acct *models.Account) error {
		acct.Contacts = strings.Join(contacts, ",")
		return nil
	})
}

func (s *sqlStoreImpl) UpdateAccountKey(ctx context.Context, acctID string, key string) (*Account, error) {
	return s.updateAccount(ctx, acctID, func(acct *models.Account) error {
		acct.Key = key
		return nil
	})
}

func (s *sqlStoreImpl) UpdateAccountStatus(ctx context.Context, acctID string, status acmeclient.AccountStatus) (*Account, error) {
	return s.updateAccount(ctx, acctID, func(acct *models.Account) error {
		acct.Status = status.String()
		return nil
	})
}

func (s *sqlStoreImpl) CreateOrder(ctx context.Context, order *Order) (*Order, error) {
	if err := helper.ValidateStruct(order); err != nil {
		return nil, err
	}

	orderRef := &models.Order{
		ID:        shortuuid.New(),
		AccountID: order.AccountID,
		Status:    order.Status.String(),
	}

	goxp.IfThen(order.Expires != nil, func() { orderRef.Expires = &order.Expires.Time })
	goxp.IfThen(order.NotBefore != nil, func() { orderRef.NotBefore = &order.NotBefore.Time })
	goxp.IfThen(order.NotAfter != nil, func() { orderRef.NotAfter = &order.NotAfter.Time })

	if order.Error != nil {
		if data, err := json.Marshal(order.Error); err == nil {
			orderRef.Error = string(data)
		}
	}

	if tx := s.db.WithContext(ctx).Create(orderRef); tx.Error != nil {
		return nil, errors.Wrap(gormx.ConvertSQLError(tx.Error), "order create failed")
	}

	for _, ident := range order.Identifiers {
		identRef := &models.Identifier{
			OrderID: &orderRef.ID,
			Type:    ident.Type.String(),
			Value:   ident.Value,
		}

		if tx := s.db.WithContext(ctx).Create(identRef); tx.Error != nil {
			// TODO cleanup order records with transactions
			return nil, errors.Wrap(gormx.ConvertSQLError(tx.Error), "identifier create failed")
		}
		orderRef.Identifiers = append(orderRef.Identifiers, *identRef)
	}

	return modelsToOrder(orderRef), nil
}

type ListOrderOpts struct {
	ID string
}

func (s *sqlStoreImpl) ListOrder(ctx context.Context, opts ListOrderOpts) ([]*Order, error) {
	results, err := s.listOrder(ctx, opts)
	if err != nil {
		return nil, err
	}

	return fx.Map(results, func(ord *models.Order) *Order { return modelsToOrder(ord) }), nil
}

func (s *sqlStoreImpl) listOrder(ctx context.Context, opts ListOrderOpts) ([]*models.Order, error) {
	w := &models.Order{
		ID: opts.ID,
	}

	var results []*models.Order
	if tx := s.db.WithContext(ctx).Order("created_at").Preload("Identifiers").Preload("Authz").Preload("Certificate").Find(&results, w); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return results, nil
}

func timeToTimestamp(t *time.Time) *common.Timestamp {
	return fx.TernaryCF(t == nil, func() *common.Timestamp { return nil }, func() *common.Timestamp { return common.NewTimestampP(t) })
}

func timestampToTime(t *common.Timestamp) *time.Time {
	return fx.TernaryCF(t == nil, func() *time.Time { return nil }, func() *time.Time { return &t.Time })
}

func modelsToOrder(order *models.Order) *Order {
	ref := &Order{
		Order: &acmeclient.Order{
			OrderResource: acmeclient.OrderResource{
				Status:      acmeclient.OrderStatus(order.Status),
				Expires:     timeToTimestamp(order.Expires),
				Identifiers: fx.Map(order.Identifiers, func(x models.Identifier) common.Identifier { return modelsToIdentifier(&x) }),
				NotBefore:   timeToTimestamp(order.NotBefore),
				NotAfter:    timeToTimestamp(order.NotAfter),
				Authz:       fx.Map(order.Authz, func(authz models.Authz) string { return authz.ID }),
				Certificate: fx.TernaryCF(order.Certificate == nil, func() string { return "" }, func() string { return order.Certificate.ID }),
			},
			ID: order.ID,
		},
		AccountID: order.AccountID,
	}

	if order.Error != "" {
		var problem common.ProblemDetail
		if err := json.Unmarshal([]byte(order.Error), &problem); err == nil {
			ref.Error = &problem
		}
	}

	return ref
}

func modelsToIdentifier(ident *models.Identifier) common.Identifier {
	return common.Identifier{
		Type:  common.IdentifierType(ident.Type),
		Value: ident.Value,
	}
}

func (s *sqlStoreImpl) GetOrder(ctx context.Context, orderID string) (*Order, error) {
	order, err := s.getOrder(ctx, orderID)
	if err != nil {
		return nil, err
	}

	return modelsToOrder(order), nil
}

func (s *sqlStoreImpl) getOrder(ctx context.Context, orderID string) (*models.Order, error) {
	orders, err := s.listOrder(ctx, ListOrderOpts{
		ID: orderID,
	})
	if err != nil {
		return nil, err
	}

	switch len(orders) {
	case 0:
		return nil, ErrOrderNotFound
	case 1:
		return orders[0], nil
	default:
		return nil, ErrMultipleRecords
	}
}

func (s *sqlStoreImpl) updateOrder(ctx context.Context, orderID string, fn func(order *models.Order) error) (*Order, error) {
	order, err := s.getOrder(ctx, orderID)
	if err != nil {
		return nil, err
	}

	if err := fn(order); err != nil {
		return nil, err
	}

	if tx := s.db.WithContext(ctx).Preload("Identifiers").Preload("Authz").Preload("Certificate").Save(order); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return modelsToOrder(order), nil
}

func (s *sqlStoreImpl) UpdateOrderStatus(ctx context.Context, orderID string, status acmeclient.OrderStatus) (*Order, error) {
	return s.updateOrder(ctx, orderID, func(order *models.Order) error {
		order.Status = status.String()
		return nil
	})
}

func (s *sqlStoreImpl) CreateAuthz(ctx context.Context, authz *Authz) (*Authz, error) {
	if err := helper.ValidateStruct(authz); err != nil {
		return nil, err
	}

	authzRef := authzToModel(authz)
	authzRef.ID = shortuuid.New()
	if tx := s.db.WithContext(ctx).Create(authzRef); tx.Error != nil {
		return nil, errors.Wrap(gormx.ConvertSQLError(tx.Error), "authorization create failed")
	}

	identRef := &models.Identifier{
		ID:      shortuuid.New(),
		AuthzID: &authzRef.ID,
		Type:    authz.Identifier.Type.String(),
		Value:   authz.Identifier.Value,
	}

	if tx := s.db.WithContext(ctx).Create(identRef); tx.Error != nil {
		// TODO cleanup order records with transactions
		return nil, errors.Wrap(gormx.ConvertSQLError(tx.Error), "identifier create failed")
	}
	authzRef.Identifier = *identRef

	return modelToAuthz(authzRef), nil
}

func authzToModel(authz *Authz) *models.Authz {
	return &models.Authz{
		ID:        authz.ID,
		AccountID: authz.AccountID,
		OrderID:   authz.OrderID,
		Status:    authz.Status.String(),
		Expires:   timestampToTime(authz.Expires),
		Wildcard:  authz.Wildcard,
	}
}

func modelToAuthz(authz *models.Authz) *Authz {
	return &Authz{
		ID:        authz.ID,
		AccountID: authz.AccountID,
		OrderID:   authz.OrderID,
		Status:    acmeclient.AuthzStatus(authz.Status),
		Expires:   common.NewTimestampP(authz.Expires),
		Identifier: common.Identifier{
			Type:  common.IdentifierType(authz.Identifier.Type),
			Value: authz.Identifier.Value,
		},
		Challenges: fx.Map(authz.Challenges, func(ch *models.Challenge) *Challenge { return modelsToChallenge(ch) }),
		Wildcard:   false,
	}
}

type ListAuthzOpts struct {
	ID      string
	OrderID string
	Status  acmeclient.AuthzStatus
}

func (s *sqlStoreImpl) ListAuthz(ctx context.Context, opts ListAuthzOpts) ([]*Authz, error) {
	results, err := s.listAuthz(ctx, opts)
	if err != nil {
		return nil, err
	}

	return fx.Map(results, func(authz *models.Authz) *Authz { return modelsToAuthz(authz) }), nil
}

func (s *sqlStoreImpl) listAuthz(ctx context.Context, opts ListAuthzOpts) ([]*models.Authz, error) {
	w := &models.Authz{
		ID:      opts.ID,
		OrderID: opts.OrderID,
		Status:  opts.Status.String(),
	}

	var results []*models.Authz
	if tx := s.db.WithContext(ctx).Order("created_at").Preload("Identifier").Preload("Challenges").Find(&results, w); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return results, nil
}

func modelsToAuthz(authz *models.Authz) *Authz {
	return &Authz{
		ID:         authz.ID,
		AccountID:  authz.AccountID,
		OrderID:    authz.OrderID,
		Status:     acmeclient.AuthzStatus(authz.Status),
		Expires:    common.NewTimestampP(authz.Expires),
		Identifier: modelsToIdentifier(&authz.Identifier),
		Challenges: fx.Map(authz.Challenges, func(ch *models.Challenge) *Challenge { return modelsToChallenge(ch) }),
		Wildcard:   false,
	}
}

func modelsToChallenge(ch *models.Challenge) *Challenge {
	chal := &Challenge{
		Challenge: &acmeclient.Challenge{
			Type:       acmeclient.ChallengeType(ch.Type),
			Token:      ch.Token,
			Status:     acmeclient.ChallengeStatus(ch.Status),
			Validated:  common.NewTimestampP(ch.Validated),
			RetryAfter: timeToTimestamp(ch.RetryAfter),
		},
		ID:      ch.ID,
		AuthzID: ch.AuthzID,
	}

	var problem common.ProblemDetail
	if err := json.Unmarshal([]byte(ch.Error), &problem); err == nil {
		chal.Error = &problem
	} else {
		chal.Error = &common.ProblemDetail{
			Title: ch.Error,
		}
	}

	return chal
}

func (s *sqlStoreImpl) GetAuthz(ctx context.Context, authzID string) (*Authz, error) {
	authz, err := s.getAuthz(ctx, authzID)
	if err != nil {
		return nil, err
	}

	return modelsToAuthz(authz), nil
}

func (s *sqlStoreImpl) getAuthz(ctx context.Context, authzID string) (*models.Authz, error) {
	authz, err := s.listAuthz(ctx, ListAuthzOpts{
		ID: authzID,
	})
	if err != nil {
		return nil, err
	}

	switch len(authz) {
	case 0:
		return nil, ErrAuthzNotFound
	case 1:
		return authz[0], nil
	default:
		return nil, ErrMultipleRecords
	}
}

func (s *sqlStoreImpl) updateAuthz(ctx context.Context, authzID string, fn func(authz *models.Authz) error) (*Authz, error) {
	authz, err := s.getAuthz(ctx, authzID)
	if err != nil {
		return nil, err
	}

	if err := fn(authz); err != nil {
		return nil, err
	}

	if tx := s.db.Save(authz); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return modelToAuthz(authz), nil
}

func (s *sqlStoreImpl) UpdateAuthzStatus(ctx context.Context, authzID string, status acmeclient.AuthzStatus) (*Authz, error) {
	return s.updateAuthz(ctx, authzID, func(authz *models.Authz) error {
		authz.Status = status.String()
		return nil
	})
}

type ListChallengesOpts struct {
	ID      string
	AuthzID string
	Status  acmeclient.ChallengeStatus
}

func (s *sqlStoreImpl) ListChallenges(ctx context.Context, opts ListChallengesOpts) ([]*Challenge, error) {
	results, err := s.listChallenges(ctx, opts)
	if err != nil {
		return nil, err
	}

	return fx.Map(results, func(ch *models.Challenge) *Challenge { return modelsToChallenge(ch) }), nil
}

func (s *sqlStoreImpl) listChallenges(ctx context.Context, opts ListChallengesOpts) ([]*models.Challenge, error) {
	w := &models.Challenge{
		ID:      opts.ID,
		AuthzID: opts.AuthzID,
		Status:  opts.Status.String(),
	}

	var results []*models.Challenge
	if tx := s.db.WithContext(ctx).Order("created_at").Find(&results, w); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return results, nil
}

func (s *sqlStoreImpl) GetChallenge(ctx context.Context, chalID string) (challenge *Challenge, err error) {
	chal, err := s.getChallenge(ctx, chalID)
	if err != nil {
		return nil, err
	}

	return modelsToChallenge(chal), nil
}

func (s *sqlStoreImpl) getChallenge(ctx context.Context, chID string) (challenge *models.Challenge, err error) {
	authz, err := s.listChallenges(ctx, ListChallengesOpts{
		ID: chID,
	})
	if err != nil {
		return nil, err
	}

	switch len(authz) {
	case 0:
		return nil, ErrAuthzNotFound
	case 1:
		return authz[0], nil
	default:
		return nil, ErrMultipleRecords
	}
}

func (s *sqlStoreImpl) CreateChallenge(ctx context.Context, chal *Challenge) (*Challenge, error) {
	if err := helper.ValidateStruct(chal); err != nil {
		return nil, err
	}

	chalRef := &models.Challenge{
		ID:        shortuuid.New(),
		AuthzID:   chal.AuthzID,
		Type:      chal.Type.String(),
		Token:     chal.Token,
		Status:    chal.Status.String(),
		Validated: timestampToTime(chal.Validated),
		Error:     fx.TernaryCF(chal.Error == nil, func() string { return "" }, func() string { return helper.MarshalJSON(chal.Error) }),
	}
	if tx := s.db.WithContext(ctx).Create(chalRef); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return modelsToChallenge(chalRef), nil
}

func (s *sqlStoreImpl) updateChallenge(ctx context.Context, chalID string, updateFn func(chal *models.Challenge) bool) (*Challenge, error) {
	chal, err := s.getChallenge(ctx, chalID)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to update challenge")
	}

	if updateFn(chal) {
		if tx := s.db.WithContext(ctx).Save(chal); tx.Error != nil {
			return nil, gormx.ConvertSQLError(tx.Error)
		}
	}

	return modelsToChallenge(chal), nil
}

func (s *sqlStoreImpl) UpdateChallengeStatus(ctx context.Context, chalID string, status acmeclient.ChallengeStatus, validated *common.Timestamp) (*Challenge, error) {
	return s.updateChallenge(ctx, chalID, func(chal *models.Challenge) bool {
		chal.Status = status.String()
		chal.Validated = timestampToTime(validated)

		return true
	})
}

func (s *sqlStoreImpl) UpdateChallengeType(ctx context.Context, chalID string, chalType acmeclient.ChallengeType) (*Challenge, error) {
	return s.updateChallenge(ctx, chalID, func(chal *models.Challenge) bool {
		if chal.Type == chalType.String() {
			return false
		}
		chal.Type = chalType.String()
		return true
	})
}

func (s *sqlStoreImpl) UpdateChallengeError(ctx context.Context, chalID string, e error, retryAfter time.Time) (*Challenge, error) {
	return s.updateChallenge(ctx, chalID, func(chal *models.Challenge) bool {
		p := ErrToProblem(e)
		chal.Error = helper.MarshalJSON(p)
		chal.RetryAfter = &retryAfter

		return true
	})
}

type ListCertificateOpts struct {
	ID      string
	OrderID string
	Hash    string // sha256 sum of certificate
}

func (s *sqlStoreImpl) ListCertificate(ctx context.Context, opts ListCertificateOpts) ([]*Certificate, error) {
	results, err := s.listCertificate(ctx, opts)
	if err != nil {
		return nil, err
	}

	return fx.Map(results, func(crt *models.Certificate) *Certificate { return modelsToCertificate(crt) }), nil
}

func (s *sqlStoreImpl) listCertificate(ctx context.Context, opts ListCertificateOpts) ([]*models.Certificate, error) {
	w := &models.Certificate{
		ID:      opts.ID,
		OrderID: opts.OrderID,
		Hash:    opts.Hash,
	}

	var results []*models.Certificate
	if tx := s.db.WithContext(ctx).Order("created_at").Find(&results, w); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return results, nil
}

func modelsToCertificate(cert *models.Certificate) *Certificate {
	return &Certificate{
		ID:           cert.ID,
		Chain:        cert.Chain,
		OrderID:      cert.OrderID,
		Hash:         cert.Hash,
		RevokeReason: x509types.StrToRevokeReason(cert.RevokeReason),
		RevokedAt:    common.NewTimestampP(cert.RevokedAt),
	}
}

func (s *sqlStoreImpl) GetCertificate(ctx context.Context, certID string) (*Certificate, error) {
	cert, err := s.getCertificate(ctx, certID)
	if err != nil {
		return nil, err
	}

	return modelsToCertificate(cert), nil
}

func (s *sqlStoreImpl) getCertificate(ctx context.Context, ID string) (*models.Certificate, error) {
	certs, err := s.listCertificate(ctx, ListCertificateOpts{
		ID: ID,
	})
	if err != nil {
		return nil, err
	}

	switch len(certs) {
	case 0:
		return nil, ErrCertNotFound
	case 1:
		return certs[0], nil
	default:
		return nil, ErrMultipleRecords
	}
}

func (s *sqlStoreImpl) CreateCertificate(ctx context.Context, cert *Certificate) (*Certificate, error) {
	if err := helper.ValidateStruct(cert); err != nil {
		return nil, err
	}

	ref := &models.Certificate{
		ID:      shortuuid.New(),
		Chain:   cert.Chain,
		OrderID: cert.OrderID,
		Hash:    hex.EncodeToString(helper.SHA256Sum(cert.Chain)),
	}
	if tx := s.db.WithContext(ctx).Save(ref); tx.Error != nil {
		return nil, gormx.ConvertSQLError(tx.Error)
	}

	return modelsToCertificate(ref), nil
}

func (s *sqlStoreImpl) GetCertificateBySum(ctx context.Context, hash string) (*Certificate, error) {
	log.Debugf("GetCertificateBySum(): sum=%s, len=%d", hash, len(hash))

	certs, err := s.ListCertificate(ctx, ListCertificateOpts{
		Hash: hash,
	})
	if err != nil {
		return nil, err
	}

	switch len(certs) {
	case 0:
		return nil, ErrCertNotFound
	case 1:
		return certs[0], nil
	default:
		return nil, ErrMultipleRecords
	}
}

func (s *sqlStoreImpl) RevokeCertificate(ctx context.Context, certID string, reason x509types.RevokeReason) (*Certificate, error) {
	cert, err := s.getCertificate(ctx, certID)
	if err != nil {
		return nil, err
	}

	cert.RevokeReason = reason.String()
	t := time.Now().UTC()
	cert.RevokedAt = &t

	if tx := s.db.Save(cert); tx.Error != nil {
		return nil, tx.Error
	}

	return modelsToCertificate(cert), nil
}
