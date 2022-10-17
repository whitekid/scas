package store

import (
	"context"
	"sync"
	"time"

	"github.com/whitekid/goxp/fx"
	"github.com/whitekid/goxp/log"

	acmeclient "scas/client/acme"
	"scas/client/common"
	"scas/client/common/x509types"
	"scas/pkg/helper"
)

// memoryStoreImpl store acme data in memory
type memoryStoreImpl struct {
	nonces      map[string]time.Time
	noncesMU    sync.Mutex
	accounts    map[string]*Account
	accountsMU  sync.Mutex
	orders      map[string]*Order
	ordersMU    sync.Mutex
	authz       map[string]*Authz
	authzMU     sync.Mutex
	certs       map[string]*Certificate
	certsMU     sync.Mutex
	challenges  map[string]*Challenge
	challengeMU sync.Mutex
}

var _ Interface = (*memoryStoreImpl)(nil)

func NewMemoryStore() *memoryStoreImpl {
	store := &memoryStoreImpl{
		nonces:     make(map[string]time.Time),
		accounts:   make(map[string]*Account),
		orders:     make(map[string]*Order),
		authz:      make(map[string]*Authz),
		certs:      make(map[string]*Certificate),
		challenges: make(map[string]*Challenge),
	}

	return store
}

func (store *memoryStoreImpl) CreateProject(ctx context.Context, proj *Project) (*Project, error) {
	panic("Not Implemented")
}

func (store *memoryStoreImpl) GetProject(ctx context.Context, projID string) (*Project, error) {
	panic("Not Implemented")
}

func (store *memoryStoreImpl) CreateTerm(ctx context.Context, projID string, term *Term) (*Term, error) {
	panic("Not Implemented: CreateTerm()")
}

func (store *memoryStoreImpl) UpdateTerm(ctx context.Context, projID string, term *Term) error {
	panic("Not Implemented: UpdateTerm()")
}

func (store *memoryStoreImpl) GetTerm(ctx context.Context, projID string, termID string) (*Term, error) {
	panic("Not Implemented: GetTerm()")
}

func (store *memoryStoreImpl) ActivateTerm(ctx context.Context, projID string, termID string) error {
	panic("Not Implemented: ActivateTerm()")
}

func (store *memoryStoreImpl) CreateNonce(ctx context.Context, projID string) (string, error) {
	nonce := helper.NewID()

	store.noncesMU.Lock()
	defer store.noncesMU.Unlock()

	store.nonces[nonce] = time.Now().UTC().Add(nonceTimeout)

	return nonce, nil
}

func (store *memoryStoreImpl) ValidNonce(ctx context.Context, projID string, n string) bool {
	expire, ok := store.nonces[n]
	if !ok {
		return false
	}

	return expire.After(time.Now().UTC())
}

func (store *memoryStoreImpl) CleanupExpiredNonce(ctx context.Context) error {
	log.Infof("checking nonce timeouts...")

	now := time.Now().UTC()

	nonces := fx.FilterMap(store.nonces, func(nonce string, expire time.Time) bool { return expire.Before(now) })
	if len(nonces) == len(store.nonces) {
		return nil
	}

	store.noncesMU.Lock()
	defer store.noncesMU.Unlock()

	store.nonces = nonces

	return nil
}

func (store *memoryStoreImpl) ListAccount(ctx context.Context, opts ListAccountOpts) ([]*Account, error) {
	panic("Not Implemented")
}

func (store *memoryStoreImpl) GetAccount(ctx context.Context, projID string, acctID string) (*Account, error) {
	acct, ok := store.accounts[acctID]
	if !ok {
		return nil, ErrAccountDoesNotExist
	}

	return acct, nil
}

func (store *memoryStoreImpl) CreateAccount(ctx context.Context, acct *Account) (*Account, error) {
	if err := helper.ValidateStruct(acct); err != nil {
		return nil, err
	}

	store.accountsMU.Lock()
	defer store.accountsMU.Unlock()

	acct.ID = helper.NewID()
	store.accounts[acct.ID] = acct

	return acct, nil
}

func (store *memoryStoreImpl) GetAccountByKey(ctx context.Context, projID string, key string) (*Account, error) {
	accts := fx.FilterMap(store.accounts, func(id string, acc *Account) bool { return key == acc.Key })
	if len(accts) != 1 {
		return nil, ErrAccountDoesNotExist
	}

	for _, v := range accts {
		return v, nil
	}

	return nil, ErrAccountDoesNotExist
}

func (store *memoryStoreImpl) UpdateAccountContact(ctx context.Context, projID string, acctID string, contacts []string) (*Account, error) {
	panic("Not Implemented")
}

func (store *memoryStoreImpl) UpdateAccountKey(ctx context.Context, projID string, acctID string, key string) (*Account, error) {
	panic("Not Implemented")
}

func (store *memoryStoreImpl) UpdateAccountStatus(ctx context.Context, projID string, acctID string, status acmeclient.AccountStatus) (*Account, error) {
	panic("Not Implemented")
}

func (store *memoryStoreImpl) CreateOrder(ctx context.Context, order *Order) (*Order, error) {
	store.ordersMU.Lock()
	defer store.ordersMU.Unlock()

	order.ID = helper.NewID()
	store.orders[order.ID] = order

	return order, nil
}

func (store *memoryStoreImpl) GetOrder(ctx context.Context, orderID string) (*Order, error) {
	order, ok := store.orders[orderID]
	if !ok {
		return nil, ErrOrderNotFound
	}

	authz, err := store.ListAuthz(ctx, ListAuthzOpts{OrderID: order.ID})
	if err != nil {
		return nil, err
	}
	order.Authz = fx.Map(authz, func(authz *Authz) string { return authz.ID })

	cert, err := store.ListCertificate(ctx, ListCertificateOpts{OrderID: order.ID})
	if len(cert) == 1 {
		order.Certificate = cert[0].ID
	}

	return order, nil
}

func (store *memoryStoreImpl) UpdateOrderStatus(ctx context.Context, ID string, status acmeclient.OrderStatus) (*Order, error) {
	order, err := store.GetOrder(ctx, ID)
	if err != nil {
		return nil, err
	}

	order.Status = status
	return order, nil
}

func (store *memoryStoreImpl) CreateAuthz(ctx context.Context, authz *Authz) (*Authz, error) {
	store.authzMU.Lock()
	defer store.authzMU.Unlock()

	authz.ID = helper.NewID()
	store.authz[authz.ID] = authz

	return authz, nil
}

func (store *memoryStoreImpl) ListAuthz(ctx context.Context, opts ListAuthzOpts) ([]*Authz, error) {
	log.Debugf("ListAuthz(): opts=%+v", opts)

	filters := []func(*Authz) bool{}

	if opts.ID != "" {
		filters = append(filters, func(a *Authz) bool { return a.ID == opts.ID })
	}
	if opts.OrderID != "" {
		filters = append(filters, func(a *Authz) bool { return a.OrderID == opts.OrderID })
	}

	authz := fx.FilterMap(store.authz, func(k string, v *Authz) bool {
		for _, filter := range filters {
			if !filter(v) {
				return false
			}
		}
		return true
	})

	return fx.Values(authz), nil
}

func (store *memoryStoreImpl) GetAuthz(ctx context.Context, ID string) (*Authz, error) {
	authz, ok := store.authz[ID]
	if !ok {
		return nil, ErrAuthzNotFound
	}

	chals, err := store.ListChallenges(ctx, ListChallengesOpts{AuthzID: authz.ID})
	if err != nil {
		return nil, err
	}
	authz.Challenges = fx.Map(chals, func(ch *Challenge) *Challenge { return ch })

	return authz, nil
}

func (store *memoryStoreImpl) UpdateAuthzStatus(ctx context.Context, authzID string, status acmeclient.AuthzStatus) (*Authz, error) {
	panic("Not Implemented")
}

func (store *memoryStoreImpl) CreateCertificate(ctx context.Context, cert *Certificate) (*Certificate, error) {
	store.certsMU.Lock()
	defer store.certsMU.Unlock()

	cert.ID = helper.NewID()
	store.certs[cert.ID] = cert

	return cert, nil
}

func (store *memoryStoreImpl) ListCertificate(ctx context.Context, opts ListCertificateOpts) ([]*Certificate, error) {
	filters := []func(*Certificate) bool{}

	if opts.ID != "" {
		filters = append(filters, func(a *Certificate) bool { return a.ID == opts.ID })
	}

	if opts.OrderID != "" {
		filters = append(filters, func(a *Certificate) bool { return a.OrderID == opts.OrderID })
	}

	chals := fx.FilterMap(store.certs, func(k string, v *Certificate) bool {
		for _, filter := range filters {
			if !filter(v) {
				return false
			}
		}
		return true
	})

	return fx.Values(chals), nil
}

func (store *memoryStoreImpl) GetCertificate(ctx context.Context, ID string) (*Certificate, error) {
	cert, ok := store.certs[ID]
	if !ok {
		return nil, ErrCertNotFound
	}
	return cert, nil
}

func (store *memoryStoreImpl) GetCertificateBySum(ctx context.Context, certID string) (*Certificate, error) {
	panic("Not Implemented")
}

func (store *memoryStoreImpl) RevokeCertificate(ctx context.Context, certID string, reason x509types.RevokeReason) (*Certificate, error) {
	panic("Not Implemented")
}

func (store *memoryStoreImpl) CreateChallenge(ctx context.Context, chal *Challenge) (*Challenge, error) {
	store.challengeMU.Lock()
	defer store.challengeMU.Unlock()

	chal.ID = helper.NewID()
	store.challenges[chal.ID] = chal

	return chal, nil
}

func (store *memoryStoreImpl) ListChallenges(ctx context.Context, opts ListChallengesOpts) ([]*Challenge, error) {
	log.Debugf("ListChallenge(): opts=%+v", opts)

	filters := []func(*Challenge) bool{}

	if opts.ID != "" {
		filters = append(filters, func(a *Challenge) bool { return a.ID == opts.ID })
	}
	if opts.AuthzID != "" {
		filters = append(filters, func(a *Challenge) bool { return a.AuthzID == opts.AuthzID })
	}

	chals := fx.FilterMap(store.challenges, func(k string, v *Challenge) bool {
		for _, filter := range filters {
			if !filter(v) {
				return false
			}
		}
		return true
	})

	return fx.Values(chals), nil

}

func (store *memoryStoreImpl) GetChallenge(ctx context.Context, ID string) (challenge *Challenge, err error) {
	chal, ok := store.challenges[ID]
	if !ok {
		return nil, ErrChallengeNotFound
	}
	return chal, nil
}

func (store *memoryStoreImpl) UpdateChallengeStatus(ctx context.Context, chalID string, status acmeclient.ChallengeStatus, validated *common.Timestamp) (*Challenge, error) {
	chal, err := store.GetChallenge(ctx, chalID)
	if err != nil {
		return nil, err
	}

	chal.Status = status
	chal.Validated = validated
	return chal, nil
}

func (store *memoryStoreImpl) UpdateChallengeType(ctx context.Context, chalID string, chalType acmeclient.ChallengeType) (*Challenge, error) {
	chal, err := store.GetChallenge(ctx, chalID)
	if err != nil {
		return nil, err
	}

	chal.Type = chalType
	return chal, nil
}

func (store *memoryStoreImpl) UpdateChallengeError(ctx context.Context, chalID string, e error, retryAfter time.Time) (*Challenge, error) {
	chal, err := store.GetChallenge(ctx, chalID)
	if err != nil {
		return nil, err
	}

	panic("Not Implemented")
	// chal.Error = e.Error()
	chal.RetryAfter = common.NewTimestamp(retryAfter)
	return chal, nil

}
