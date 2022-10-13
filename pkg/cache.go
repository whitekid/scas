package pkg

import (
	"context"
	"time"
)

type Cache[K comparable, V any] interface {
	Set(ctx context.Context, k K, v V, ttl time.Duration) error
	Get(ctx context.Context, k K) (V, error)
	Delete(ctx context.Context, k K) error
	Expire(ctx context.Context, k K) error
}

func NewCache[K comparable, V any]() Cache[K, V] {
	return &cacheImpl[K, V]{}
}

type cacheImpl[K comparable, V any] struct {
}

func (cache *cacheImpl[K, V]) Set(ctx context.Context, k K, v V, ttl time.Duration) error {
	panic("not implemented") // TODO: Implement
}

func (cache *cacheImpl[K, V]) Get(ctx context.Context, k K) (V, error) {
	panic("not implemented") // TODO: Implement
}

func (cache *cacheImpl[K, V]) Delete(ctx context.Context, k K) error {
	panic("not implemented") // TODO: Implement
}

func (cache *cacheImpl[K, V]) Expire(ctx context.Context, k K) error {
	panic("not implemented") // TODO: Implement
}
