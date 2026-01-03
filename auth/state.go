package auth

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// StateMap is a thread-safe map for storing OAuth2 state parameters with automatic expiry.
type StateMap struct {
	mu sync.RWMutex
	m  map[string]bool
}

// NewStateMap creates a new initialized StateMap.
func NewStateMap() *StateMap {
	return &StateMap{
		m: make(map[string]bool),
	}
}

// Generate creates a new state string that expires after the given seconds.
func (s *StateMap) Generate(seconds int) string {
	state := uuid.NewString()

	s.mu.Lock()
	s.m[state] = true
	s.mu.Unlock()

	go func() {
		<-time.After(time.Duration(seconds) * time.Second)
		s.mu.Lock()
		delete(s.m, state)
		s.mu.Unlock()
	}()

	return state
}

// Validate checks if the state exists in the map.
func (s *StateMap) Validate(state string) bool {
	s.mu.RLock()
	_, ok := s.m[state]
	s.mu.RUnlock()
	return ok
}

// ValidateOnce checks if the state exists and removes it from the map.
func (s *StateMap) ValidateOnce(state string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.m[state]; ok {
		delete(s.m, state)
		return true
	}
	return false
}

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

// Store saves a value with the given key, auto-expiring after the given seconds.
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

// Pop retrieves and removes the value for the given key.
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
