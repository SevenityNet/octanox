package auth

import (
	"context"
	"sync"
	"time"
)

// OAuthStateStore stores ephemeral OAuth2 values with automatic expiry.
// Implementations must support atomic Pop (get + delete) to prevent replay attacks.
type OAuthStateStore interface {
	// Set stores a value keyed by key, auto-expiring after ttl.
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	// Pop atomically retrieves and removes the value. Returns ("", nil) if not found or expired.
	Pop(ctx context.Context, key string) (string, error)
}

// MemoryStateStore is an in-memory OAuthStateStore with goroutine-based TTL expiry.
// It is the default store used by OAuth2BearerAuthenticator.
type MemoryStateStore struct {
	mu sync.Mutex
	m  map[string]string
}

// NewMemoryStateStore creates a new MemoryStateStore.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{
		m: make(map[string]string),
	}
}

// Set stores a value with automatic expiry after ttl.
func (s *MemoryStateStore) Set(_ context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	s.m[key] = value
	s.mu.Unlock()

	go func() {
		<-time.After(ttl)
		s.mu.Lock()
		delete(s.m, key)
		s.mu.Unlock()
	}()

	return nil
}

// Pop atomically retrieves and removes the value. Returns ("", nil) if not found.
func (s *MemoryStateStore) Pop(_ context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	val, ok := s.m[key]
	if ok {
		delete(s.m, key)
		return val, nil
	}
	return "", nil
}

// FuncStateStore adapts arbitrary set/pop functions into an OAuthStateStore.
// Use this to integrate external stores (Redis, Memcached, database) without
// adding dependencies to Octanox.
//
// Example with go-redis:
//
//	store := auth.NewFuncStateStore(
//	    func(ctx context.Context, key, value string, ttl time.Duration) error {
//	        return redisClient.Set(ctx, key, value, ttl).Err()
//	    },
//	    func(ctx context.Context, key string) (string, error) {
//	        val, err := redisClient.GetDel(ctx, key).Result()
//	        if errors.Is(err, redis.Nil) { return "", nil }
//	        return val, err
//	    },
//	)
type FuncStateStore struct {
	setFn func(ctx context.Context, key, value string, ttl time.Duration) error
	popFn func(ctx context.Context, key string) (string, error)
}

// NewFuncStateStore creates a new FuncStateStore with the given set and pop functions.
func NewFuncStateStore(
	setFn func(ctx context.Context, key, value string, ttl time.Duration) error,
	popFn func(ctx context.Context, key string) (string, error),
) *FuncStateStore {
	return &FuncStateStore{setFn: setFn, popFn: popFn}
}

// Set stores a value by delegating to the wrapped set function.
func (s *FuncStateStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return s.setFn(ctx, key, value, ttl)
}

// Pop atomically retrieves and removes a value by delegating to the wrapped pop function.
func (s *FuncStateStore) Pop(ctx context.Context, key string) (string, error) {
	return s.popFn(ctx, key)
}
