package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/sevenitynet/octanox/model"
)

// BasicAuthenticator implements HTTP Basic authentication.
type BasicAuthenticator struct {
	provider UserProvider
}

// NewBasicAuthenticator creates a new BasicAuthenticator.
func NewBasicAuthenticator(provider UserProvider) *BasicAuthenticator {
	return &BasicAuthenticator{
		provider: provider,
	}
}

// Method returns the authentication method.
func (a *BasicAuthenticator) Method() AuthenticationMethod {
	return AuthenticationMethodBasic
}

// Authenticate extracts and validates Basic auth credentials from the request.
func (a *BasicAuthenticator) Authenticate(c *gin.Context) (model.User, error) {
	username, password, ok := c.Request.BasicAuth()
	if !ok {
		return nil, nil
	}

	user, err := a.provider.ProvideByUserPass(username, password)
	if err != nil {
		return nil, err
	}

	return user, nil
}
