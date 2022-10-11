package manager

import (
	"context"

	"github.com/pkg/errors"

	"scas/acme/store"
	acmeclient "scas/client/acme"
)

func (m *Manager) CreateProject(ctx context.Context, name string) (*store.Project, error) {
	return m.store.CreateProject(ctx, &store.Project{Name: name})
}

func (m *Manager) GetProject(ctx context.Context, projID string) (*store.Project, error) {
	return m.store.GetProject(ctx, projID)
}

func (m *Manager) CreateTerm(ctx context.Context, projID string, in *acmeclient.Term) (*store.Term, error) {
	created, err := m.store.CreateTerm(ctx, projID, &store.Term{
		ProjectID: projID,
		Content:   in.Content,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "fail to create term")
	}

	if in.Active {
		if err := m.updateActiveTerm(ctx, projID, created.ID); err != nil {
			return nil, errors.Wrapf(err, "fail to update active term")
		}
	}

	return created, nil
}

func (m *Manager) UpdateTerm(ctx context.Context, projID string, in *acmeclient.Term) (*store.Term, error) {
	term, err := m.store.GetTerm(ctx, projID, in.ID)
	if err != nil {
		return nil, err
	}

	term.Content = in.Content
	updated, err := m.store.UpdateTerm(ctx, projID, term)
	if err != nil {
		return nil, err
	}

	if in.Active {
		if err := m.updateActiveTerm(ctx, projID, updated.ID); err != nil {
			return nil, errors.Wrapf(err, "fail to update active term")
		}
	}

	return updated, nil
}

func (m *Manager) updateActiveTerm(ctx context.Context, projID string, termID string) error {
	proj, err := m.GetProject(ctx, projID)
	if err != nil {
		return errors.Wrapf(err, "fail to update active term")
	}

	if proj.TermID == termID {
		return nil
	}

	return m.store.ActivateTerm(ctx, projID, termID)
}

func (m *Manager) GetTerm(ctx context.Context, projID string, termID string) (*store.Term, error) {
	term, err := m.store.GetTerm(ctx, projID, termID)
	if err != nil {
		return nil, err
	}

	return term, nil
}
