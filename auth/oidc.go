package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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
	// Fetch discovery
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	resp, err := http.Get(discoveryURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var disc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return err
	}
	if disc.Issuer == "" || disc.JWKSURI == "" {
		return errors.New("invalid discovery document")
	}

	// Fetch JWKS
	resp2, err := http.Get(disc.JWKSURI)
	if err != nil {
		return err
	}
	defer resp2.Body.Close()
	var jwks jwksResponse
	if err := json.NewDecoder(resp2.Body).Decode(&jwks); err != nil {
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
