package manager

import (
	"context"
	"time"

	"scas/acme/store"
)

// Manager acme manager
// Depreciated 필요없을 것 같은데... manager에서는 ID만 관리하고 API에서 URL 수정하는 것이 좋을 듯..
type Manager struct {
	store store.Interface

	termUpdatedAt time.Time // TODO termUpdatedA는 프젝트마다 다를 것...
	challenger    *Challenger
}

// New create new acme manager
func New(store store.Interface) *Manager {
	m := &Manager{
		store: store,
	}
	m.challenger = newChallenger(m, store)
	return m
}

func (m *Manager) SetTermUpdated(t time.Time) { m.termUpdatedAt = t }

func (m *Manager) ValidNonce(ctx context.Context, projID string, n string) bool {
	return m.store.ValidNonce(ctx, projID, n)
}

func (m *Manager) NewNonce(ctx context.Context, projID string) (string, error) {
	return m.store.CreateNonce(ctx, projID)
}

func (m *Manager) CheckNonceTimeout(ctx context.Context) error {
	return m.store.CleanupExpiredNonce(ctx)
}

func (m *Manager) GetAccountByKey(ctx context.Context, projID string, JWK string) (*store.Account, error) {
	return m.store.GetAccountByKey(ctx, projID, JWK)
}
