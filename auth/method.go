package auth

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
