package octanox

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// UserProvider is an interface that allows the authentication module to access the user data.
type UserProvider interface {
	// ProvideByUserPass provides the user data for the given username and password. If the user data cannot be provided, it should return an error.
	ProvideByUserPass(username, password string) (User, error)
	// ProvideByID provides the user data for the given user ID. If the user data cannot be provided, it should return an error.
	// This should be used to provide the user data when the authentication is called, like providing it by the user ID in the token.
	ProvideByID(id uuid.UUID) (User, error)
	// ProvideByApiKey provides the user data for the given API key. If the user data cannot be provided, it should return an error.
	ProvideByApiKey(apiKey string) (User, error)
}

// OAuth2UserProvider is an interface that allows the authentication module to access the user data from OAuth2 providers.
type OAuth2UserProvider interface {
	// ProvideForLogin provides the user data for the given OAuth2 access token. If the user data cannot be provided, it should return an error.
	ProvideForLogin(oauth2AccessToken string) (User, error)
	// ProvideByID provides the user data for the given user ID. If the user data cannot be provided, it should return an error.
	ProvideByID(id uuid.UUID) (User, error)
}

// AuthenticationMethod is an enum that defines the authentication methods.
type AuthenticationMethod int

const (
	// AuthenticationMethodBearer is the Bearer authentication method.
	AuthenticationMethodBearer AuthenticationMethod = iota
	// AuthenticationMethodBasic is the Basic authentication method.
	AuthenticationMethodBasic
	// AuthenticationMethodApiKey is the API key authentication method.
	AuthenticationMethodApiKey
	// AuthenticationMethodBearerOAuth2 is the Bearer OAuth2 authentication method.
	AuthenticationMethodBearerOAuth2
)

// Authenticator is an struct that defines the authentication module.
type Authenticator interface {
	// Method returns the authentication method.
	Method() AuthenticationMethod

	// Authenticate authenticates the client request. Gets the client request context and returns the authenticated user.
	// If the authentication fails, it should return nil.
	Authenticate(c *gin.Context) (User, error)
}

// AuthenticatorBuilder is a struct that helps build the Authenticator.
type AuthenticatorBuilder struct {
	instance *Instance
	provider interface{}
}

// Plugs in the authentication module into Octanox.
func (i *Instance) Authenticate(provider interface{}) *AuthenticatorBuilder {
	if i.Authenticator != nil {
		panic("octanox: authenticator already exists")
	}

	return &AuthenticatorBuilder{i, provider}
}

// Bearer creates a new BearerAuthenticator with the given secret and plugs it into the Authenticator.
// The basePath is the base path for the authentication routes.
// The secret is the secret key used to sign the JWT token.
// Defaults to 1 day for the token expiration time.
func (b *AuthenticatorBuilder) Bearer(secret, basePath string) *BearerAuthenticator {
	userProvider, ok := b.provider.(UserProvider)
	if !ok {
		panic("octanox: invalid user provider; expected UserProvider")
	}

	bearer := &BearerAuthenticator{
		provider: userProvider,
		secret:   []byte(secret),
		exp:      86400,
	}

	bearer.registerRoutes(b.instance.Gin.Group(basePath))

	b.instance.Authenticator = bearer
	b.instance.authLoginBasePath = basePath

	return bearer
}

// BearerOAuth2 creates a new OAuth2BearerAuthenticator with the given OAuth2 parameters and plugs it into the Authenticator.
// The basePath is the base path for the authentication routes.
// The clientId is the OAuth2 client ID.
// The clientSecret is the OAuth2 client secret.
// The oauth2Endpoint is the OAuth2 endpoint.
// The scopes is the list of scopes to request.
// The domain is the domain of this application. The domain must not have a trailing slash. The domain should contain any prefix
// The loginSuccessRedirect is the URL to redirect to after a successful login.
// The secret is the secret key used to sign the JWT token.
func (b *AuthenticatorBuilder) BearerOAuth2(oauth2Endpoint oauth2.Endpoint, scopes []string, clientId, clientSecret, domain, loginSuccessRedirect, secret, basePath string) *OAuth2BearerAuthenticator {
	userProvider, ok := b.provider.(OAuth2UserProvider)
	if !ok {
		panic("octanox: invalid user provider; expected OAuth2UserProvider")
	}

	bearer := &OAuth2BearerAuthenticator{
		provider:             userProvider,
		loginSuccessRedirect: loginSuccessRedirect,
		config: oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Endpoint:     oauth2Endpoint,
			RedirectURL:  domain + basePath + "/oauth2/callback",
			Scopes:       scopes,
		},
		secret:   []byte(secret),
		states:   make(StateMap),
		pkces:    make(StringStateMap),
		nonces:   make(StringStateMap),
		exp:      86400,
		instance: b.instance,
	}

	bearer.registerRoutes(b.instance.Gin.Group(basePath))

	b.instance.Authenticator = bearer
	b.instance.authLoginBasePath = basePath

	return bearer
}

// Basic creates a new BasicAuthenticator and plugs it into the Authenticator.
func (b *AuthenticatorBuilder) Basic() *BasicAuthenticator {
	userProvider, ok := b.provider.(UserProvider)
	if !ok {
		panic("octanox: invalid user provider; expected UserProvider")
	}

	basic := &BasicAuthenticator{
		provider: userProvider,
	}

	b.instance.Authenticator = basic

	return basic
}

// ApiKey creates a new ApiKeyAuthenticator and plugs it into the Authenticator.
func (b *AuthenticatorBuilder) ApiKey() *ApiKeyAuthenticator {
	userProvider, ok := b.provider.(UserProvider)
	if !ok {
		panic("octanox: invalid user provider; expected UserProvider")
	}

	apiKey := &ApiKeyAuthenticator{
		provider: userProvider,
	}

	b.instance.Authenticator = apiKey

	return apiKey
}
