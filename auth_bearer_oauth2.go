package octanox

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type OAuth2BearerAuthenticator struct {
	provider             OAuth2UserProvider
	config               oauth2.Config
	loginSuccessRedirect string
	secret               []byte
	exp                  int64
	states               StateMap
	pkces                StringStateMap
	nonces               StringStateMap
	// Optional OIDC ID token validation
	validateIDToken bool
	oidcIssuer      string
	// Cookie-based auth settings
	useCookies   bool
	cookieName   string
	cookieDomain string
	cookieSecure bool
	// Reference to the Instance for tracking cookie auth state
	instance *Instance
}

// SetExp sets the expiration time for the token.
func (a *OAuth2BearerAuthenticator) SetExp(exp int64) {
	a.exp = exp
}

func (a *OAuth2BearerAuthenticator) Method() AuthenticationMethod {
	return AuthenticationMethodBearerOAuth2
}

func (a *OAuth2BearerAuthenticator) Authenticate(c *gin.Context) (User, error) {
	var tokenString string

	// If cookie auth is enabled, check cookie first
	if a.useCookies {
		if cookie, err := c.Cookie(a.cookieName); err == nil && cookie != "" {
			tokenString = cookie
		}
	}

	// Fall back to Authorization header (for API clients and backwards compatibility)
	if tokenString == "" {
		header := c.GetHeader("Authorization")
		if header != "" && len(header) > 7 && strings.HasPrefix(header, "Bearer ") {
			tokenString = header[7:]
		}
	}

	if tokenString == "" {
		return nil, nil
	}

	userID := a.extractToken(tokenString)
	if userID == nil {
		return nil, nil
	}

	user, err := a.provider.ProvideByID(*userID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (a *OAuth2BearerAuthenticator) login(c *gin.Context) {
	// Generate a state and PKCE pair
	state := a.states.Generate(300)
	verifier, challenge := generatePKCE()
	a.pkces.Store(state, verifier, 600)
	nonce := generateNonce()
	a.nonces.Store(state, nonce, 600)

	// Request authorization code with PKCE (S256)
	url := a.config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", nonce),
		// Ensure scopes are sent as a space-delimited string
		oauth2.SetAuthURLParam("scope", strings.Join(a.config.Scopes, " ")),
	)

	c.Redirect(302, url)
}

func (a *OAuth2BearerAuthenticator) callback(c *gin.Context) {
	state := c.Query("state")
	if !a.states.ValidateOnce(state) {
		c.String(400, "invalid state")
		return
	}

	code := c.Query("code")

	// Retrieve PKCE verifier for this state
	verifier := a.pkces.Pop(state)
	if verifier == "" {
		c.String(400, "missing PKCE verifier")
		return
	}
	// Retrieve expected nonce for this state (may be empty if not used)
	expectedNonce := a.nonces.Pop(state)

	token, err := a.config.Exchange(context.Background(), code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		c.String(400, "Token Exchange Failed")
		return
	}

	// Optionally validate ID token using OIDC discovery + JWKS
	if a.validateIDToken {
		if raw := token.Extra("id_token"); raw != nil {
			idToken, _ := raw.(string)
			if err := validateIDTokenWithIssuer(idToken, a.oidcIssuer, a.config.ClientID, expectedNonce); err != nil {
				c.String(400, "Invalid ID Token")
				return
			}
		} else {
			c.String(400, "Missing ID Token")
			return
		}
	}

	user, err := a.provider.ProvideForLogin(token.AccessToken)
	if err != nil {
		panic(err)
	}

	if user == nil {
		c.String(400, "User not found")
		return
	}

	jwt, err := a.createToken(user)
	if err != nil {
		panic("octanox: failed to create token")
	}

	// Cookie-based auth: set HTTP-only cookie and redirect without token in URL
	if a.useCookies {
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(
			a.cookieName,   // name
			jwt,            // value
			int(a.exp),     // max age in seconds
			"/",            // path
			a.cookieDomain, // domain
			a.cookieSecure, // secure (HTTPS only)
			true,           // httpOnly (not accessible via JavaScript)
		)
		c.Redirect(302, a.loginSuccessRedirect)
		return
	}

	// Bearer token auth: pass token in URL (legacy behavior)
	c.Redirect(302, a.loginSuccessRedirect+"?token="+jwt)
}

func (a *OAuth2BearerAuthenticator) registerRoutes(r *gin.RouterGroup) {
	r.GET("/login", a.login)
	r.GET("/oauth2/callback", a.callback)
	// Always register logout endpoint for cookie-based auth
	r.POST("/logout", a.logout)
}

// logout clears the authentication cookie and returns success
func (a *OAuth2BearerAuthenticator) logout(c *gin.Context) {
	if a.useCookies {
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(
			a.cookieName,   // name
			"",             // value (empty to clear)
			-1,             // max age -1 = delete immediately
			"/",            // path
			a.cookieDomain, // domain
			a.cookieSecure, // secure
			true,           // httpOnly
		)
	}
	c.JSON(200, gin.H{"message": "Logged out successfully"})
}

// EnableOIDCValidation enforces validation of ID token against the given issuer using JWKS.
func (a *OAuth2BearerAuthenticator) EnableOIDCValidation(issuer string) *OAuth2BearerAuthenticator {
	a.oidcIssuer = issuer
	a.validateIDToken = true
	return a
}

// EnableCookieAuth enables cookie-based authentication instead of URL token passing.
// When enabled, the OAuth callback will set an HTTP-only cookie with the JWT token
// instead of passing it via URL query parameter.
// Parameters:
//   - cookieName: The name of the cookie to set (e.g., "mtnai_token")
//   - cookieDomain: The domain for the cookie (e.g., ".mtnmedia.group" for cross-subdomain)
//   - secure: Whether to only send the cookie over HTTPS
func (a *OAuth2BearerAuthenticator) EnableCookieAuth(cookieName, cookieDomain string, secure bool) *OAuth2BearerAuthenticator {
	a.useCookies = true
	a.cookieName = cookieName
	a.cookieDomain = cookieDomain
	a.cookieSecure = secure
	// Update the instance to track that cookie auth is enabled
	if a.instance != nil {
		a.instance.useCookieAuth = true
	}
	return a
}

func (a *OAuth2BearerAuthenticator) createToken(user User) (string, error) {
	currTime := time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "Octanox Auth",
		"aud": "octanox",
		"sub": user.ID(),
		"exp": time.Now().Add(time.Second * time.Duration(a.exp)).Unix(),
		"iat": currTime,
		"nbf": currTime,
		"jti": uuid.New().String(),
	})

	return token.SignedString(a.secret)
}

func (a *OAuth2BearerAuthenticator) extractToken(tokenString string) *uuid.UUID {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}

		return a.secret, nil
	})
	if err != nil {
		return nil
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		subClaim, ok := claims["sub"]
		if !ok {
			return nil
		}

		subject, err := uuid.Parse(subClaim.(string))
		if err != nil {
			return nil
		}

		return &subject
	}

	return nil
}
