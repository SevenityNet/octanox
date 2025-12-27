package octanox

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

func (s *StateMap) Validate(state string) bool {
	s.mu.RLock()
	_, ok := s.m[state]
	s.mu.RUnlock()
	return ok
}

func (s *StateMap) ValidateOnce(state string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.m[state]; ok {
		delete(s.m, state)
		return true
	}
	return false
}
