package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// GeneratePKCE returns a (verifier, challenge) pair using S256 method.
func GeneratePKCE() (string, string) {
	// Generate 32 bytes (results in 43-char base64url encoded string)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("octanox: failed to generate random bytes for PKCE: " + err.Error())
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// GenerateNonce returns a random base64url string suitable for OIDC nonce.
func GenerateNonce() string {
	b := make([]byte, 16) // 128 bits of entropy
	if _, err := rand.Read(b); err != nil {
		panic("octanox: failed to generate random bytes for nonce: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
