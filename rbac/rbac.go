package rbac

import (
	"context"
	"sync"
	"time"

	"scas/pkg/simplekv"
)

type Interface interface {
	// return true if `id` has `permission` for `role`
	HasPermission(ctx context.Context, id string, role string, permission string) (bool, error)
}

type memoryImpl struct {
	muPermission sync.Mutex
	permissions  simplekv.Interface[string, struct{}]

	backend Backend
}

// Backend RBAC backend
type Backend interface {
	HasPermission(ctx context.Context, id string, role string, permission string) (bool, error)
}

func New(backend Backend) Interface {
	return &memoryImpl{
		permissions: simplekv.New[string, struct{}](),
		backend:     backend,
	}
}

func key(id, role, permission string) string { return id + ":" + role + ":" + permission }

func (r *memoryImpl) HasPermission(ctx context.Context, id string, role string, permission string) (bool, error) {
	k := key(id, role, permission)

	_, err := r.permissions.Get(ctx, k)
	if err != nil {
		if err == simplekv.ErrNotExists && r.backend != nil {
			ok, err := r.backend.HasPermission(ctx, id, role, permission)
			if err != nil {
				return ok, err
			}

			r.permissions.Set(ctx, k, struct{}{}, time.Minute)
			return ok, nil
		}
		return false, err
	}

	return true, nil
}

type memoryBackendImpl struct {
}

func (b *memoryBackendImpl) HasPermission(ctx context.Context, id string, role string, permission string) bool {
	panic("Not Implemented")
}

// func (r *RBAC) AddPermission(id string, role string, permission string) error {
// 	return r.AddPermissionWithTimeout(id, role, permission, 5*time.Minute)
// }

// func (r *RBAC) AddPermissionWithTimeout(id string, role string, permission string, timeout time.Duration) error {
// 	r.muPermission.Lock()
// 	defer r.muPermission.Unlock()
// 	r.permissions.Set(key(id, role, permission), time.Now().UTC().Add(timeout))

// 	return nil
// }
