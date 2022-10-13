package simplekv

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/whitekid/goxp/fx"
)

type Interface[K comparable, V any] interface {
	Len() int
	Set(ctx context.Context, k K, v V, ttl time.Duration) error
	Get(ctx context.Context, k K) (V, error)
	Delete(ctx context.Context, k K) error
	Expire(ctx context.Context, k K) error
	Cleanup(ctx context.Context) error
}

var (
	ErrNotExists = errors.New("key not exists")
)

func New[K comparable, V any]() Interface[K, V] {
	return &memoryImpl[K, V]{
		values: make(map[K]*value[V]),
	}
}

type memoryImpl[K comparable, V any] struct {
	mu     sync.Mutex
	values map[K]*value[V]
}

var _ Interface[struct{}, struct{}] = (*memoryImpl[struct{}, struct{}])(nil)

type value[T any] struct {
	value  T
	expire time.Time
}

func (m *memoryImpl[K, V]) Len() int { return len(m.values) }

func (m *memoryImpl[K, V]) Set(ctx context.Context, k K, v V, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.values[k] = &value[V]{
		value:  v,
		expire: fx.Ternary(ttl == 0, time.Time{}, time.Now().UTC().Add(ttl)),
	}
	return nil
}

func (m *memoryImpl[K, V]) Get(ctx context.Context, k K) (V, error) {
	v, ok := m.values[k]
	if !ok {
		var vv V
		return vv, ErrNotExists
	}

	if !v.expire.IsZero() && v.expire.Before(time.Now()) {
		m.Delete(ctx, k)

		var vv V
		return vv, ErrNotExists
	}

	return v.value, nil
}

func (m *memoryImpl[K, V]) Delete(ctx context.Context, k K) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.values, k)
	return nil
}

func (m *memoryImpl[K, V]) Expire(ctx context.Context, k K) error {
	v, ok := m.values[k]
	if !ok {
		return ErrNotExists
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	v.expire = time.Now()

	return nil
}

func (m *memoryImpl[K, V]) Cleanup(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	m.values = fx.FilterMap(m.values, func(k K, v *value[V]) bool { return v.expire.After(now) })

	return nil
}
