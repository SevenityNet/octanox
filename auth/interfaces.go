package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sevenitynet/octanox/model"
)

// UserProvider is an interface that allows the authentication module to access the user data.
type UserProvider interface {
	// ProvideByUserPass provides the user data for the given username and password. If the user data cannot be provided, it should return an error.
	ProvideByUserPass(username, password string) (model.User, error)
	// ProvideByID provides the user data for the given user ID. If the user data cannot be provided, it should return an error.
	// This should be used to provide the user data when the authentication is called, like providing it by the user ID in the token.
	ProvideByID(id uuid.UUID) (model.User, error)
	// ProvideByApiKey provides the user data for the given API key. If the user data cannot be provided, it should return an error.
	ProvideByApiKey(apiKey string) (model.User, error)
}

// OAuth2UserProvider is an interface that allows the authentication module to access the user data from OAuth2 providers.
type OAuth2UserProvider interface {
	// ProvideForLogin provides the user data for the given OAuth2 access token. If the user data cannot be provided, it should return an error.
	ProvideForLogin(oauth2AccessToken string) (model.User, error)
	// ProvideByID provides the user data for the given user ID. If the user data cannot be provided, it should return an error.
	ProvideByID(id uuid.UUID) (model.User, error)
}

// Authenticator is an interface that defines the authentication module.
type Authenticator interface {
	// Method returns the authentication method.
	Method() AuthenticationMethod

	// Authenticate authenticates the client request. Gets the client request context and returns the authenticated user.
	// If the authentication fails, it should return nil.
	Authenticate(c *gin.Context) (model.User, error)
}
