package manager

import (
	"context"

	"scas/acme/store"
)

func (m *Manager) CreateProject(ctx context.Context, name string) (*store.Project, error) {
	return m.store.CreateProject(ctx, &store.Project{Name: name})
}

func (m *Manager) GetProject(ctx context.Context, projID string) (*store.Project, error) {
	return m.store.GetProject(ctx, projID)
}
