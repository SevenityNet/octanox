package octanox

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

// StringStateMap is a thread-safe map for storing string values by key with automatic expiry.
type StringStateMap struct {
	mu sync.RWMutex
	m  map[string]string
}

// NewStringStateMap creates a new initialized StringStateMap.
func NewStringStateMap() *StringStateMap {
	return &StringStateMap{
		m: make(map[string]string),
	}
}

func (s *StringStateMap) Store(key, value string, seconds int) {
	s.mu.Lock()
	s.m[key] = value
	s.mu.Unlock()

	go func(k string) {
		<-time.After(time.Duration(seconds) * time.Second)
		s.mu.Lock()
		delete(s.m, k)
		s.mu.Unlock()
	}(key)
}

func (s *StringStateMap) Pop(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	val, ok := s.m[key]
	if ok {
		delete(s.m, key)
		return val
	}
	return ""
}

// generatePKCE returns a (verifier, challenge) pair using S256 method.
func generatePKCE() (string, string) {
	// Generate 32 bytes (results in 43-char base64url encoded string)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("octanox: failed to generate random bytes for PKCE: " + err.Error())
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// generateNonce returns a random base64url string suitable for OIDC nonce.
func generateNonce() string {
	b := make([]byte, 16) // 128 bits of entropy
	if _, err := rand.Read(b); err != nil {
		panic("octanox: failed to generate random bytes for nonce: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
