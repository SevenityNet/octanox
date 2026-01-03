package model

import "github.com/google/uuid"

// User is an interface that defines the authenticated user model.
type User interface {
	// ID returns the user's ID.
	ID() uuid.UUID
	// HasRole checks if the user has the given role.
	HasRole(role string) bool
}
