package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// defaultOAuthHTTPTimeout bounds every outbound OAuth/OIDC call so a stalled upstream cannot hold a handler open.
const defaultOAuthHTTPTimeout = 10 * time.Second

// oidcMaxResponseBytes caps discovery/JWKS JSON reads; a JWKS with dozens of RSA keys stays well under 1 MiB.
const oidcMaxResponseBytes = 1 << 20

// boundedHTTPClient layers only a timeout onto base's transport so a host's custom transport/redirect/jar are preserved.
func boundedHTTPClient(base *http.Client, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = defaultOAuthHTTPTimeout
	}
	if base == nil {
		base = http.DefaultClient
	}
	transport := base.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: base.CheckRedirect,
		Jar:           base.Jar,
		Timeout:       timeout,
	}
}

// fetchJSONBounded GETs url with the given client and decodes a body-capped JSON response into dst.
func fetchJSONBounded(ctx context.Context, client *http.Client, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Read one byte past the cap so an oversized body is an explicit error, not a truncated-JSON decode failure.
	data, err := io.ReadAll(io.LimitReader(resp.Body, oidcMaxResponseBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > oidcMaxResponseBytes {
		return errors.New("oauth: response body exceeds size limit")
	}
	return json.Unmarshal(data, dst)
}

type oidcDiscovery struct {
	JWKSURI string `json:"jwks_uri"`
	Issuer  string `json:"issuer"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// ValidateIDTokenWithIssuer validates an OIDC ID token against the given issuer using JWKS discovery.
func ValidateIDTokenWithIssuer(idToken string, issuer string, clientID string, expectedNonce string) error {
	return validateIDTokenWithIssuer(context.Background(), boundedHTTPClient(nil, 0), idToken, issuer, clientID, expectedNonce)
}

// validateIDTokenWithIssuer runs discovery + JWKS validation over the supplied bounded client and context.
func validateIDTokenWithIssuer(ctx context.Context, client *http.Client, idToken string, issuer string, clientID string, expectedNonce string) error {
	// Fetch discovery
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	var disc oidcDiscovery
	if err := fetchJSONBounded(ctx, client, discoveryURL, &disc); err != nil {
		return err
	}
	if disc.Issuer == "" || disc.JWKSURI == "" {
		return errors.New("invalid discovery document")
	}

	// Fetch JWKS
	var jwks jwksResponse
	if err := fetchJSONBounded(ctx, client, disc.JWKSURI, &jwks); err != nil {
		return err
	}

	// Build kid -> rsa.PublicKey map
	pubByKid := map[string]*rsa.PublicKey{}
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" || k.Kid == "" {
			continue
		}
		nBytes, errN := base64.RawURLEncoding.DecodeString(k.N)
		eBytes, errE := base64.RawURLEncoding.DecodeString(k.E)
		if errN != nil || errE != nil {
			continue
		}
		n := new(big.Int).SetBytes(nBytes)
		// Common exponent values are small, we parse bytes to int
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		pub := &rsa.PublicKey{N: n, E: e}
		pubByKid[k.Kid] = pub
	}

	// Parse and validate JWT
	token, err := jwt.Parse(idToken, func(t *jwt.Token) (interface{}, error) {
		// Must be RS256
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		pub := pubByKid[kid]
		if pub == nil {
			return nil, errors.New("unknown kid")
		}
		return pub, nil
	}, jwt.WithAudience(clientID), jwt.WithIssuer(issuer), jwt.WithLeeway(30*time.Second))
	if err != nil {
		return err
	}
	if !token.Valid {
		return errors.New("invalid token")
	}
	// Check nonce if expectedNonce provided
	if expectedNonce != "" {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			nonceVal, has := claims["nonce"]
			if !has {
				return errors.New("missing nonce")
			}
			nonceStr, ok2 := nonceVal.(string)
			if !ok2 || nonceStr != expectedNonce {
				return errors.New("nonce mismatch")
			}
		}
	}
	return nil
}
