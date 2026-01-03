package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/sevenitynet/octanox/model"
)

// ApiKeyAuthenticator implements API key authentication via X-API-Key header.
type ApiKeyAuthenticator struct {
	provider UserProvider
}

// NewApiKeyAuthenticator creates a new ApiKeyAuthenticator.
func NewApiKeyAuthenticator(provider UserProvider) *ApiKeyAuthenticator {
	return &ApiKeyAuthenticator{
		provider: provider,
	}
}

// Method returns the authentication method.
func (a *ApiKeyAuthenticator) Method() AuthenticationMethod {
	return AuthenticationMethodApiKey
}

// Authenticate extracts and validates the API key from the X-API-Key header.
func (a *ApiKeyAuthenticator) Authenticate(c *gin.Context) (model.User, error) {
	apiKey := c.GetHeader("X-API-Key")
	if apiKey == "" {
		return nil, nil
	}

	user, err := a.provider.ProvideByApiKey(apiKey)
	if err != nil {
		return nil, err
	}

	return user, nil
}
