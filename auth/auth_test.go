package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sevenitynet/octanox/model"
)

// Mock user for testing
type mockUser struct {
	id    uuid.UUID
	roles []string
}

func (m *mockUser) ID() uuid.UUID       { return m.id }
func (m *mockUser) HasRole(r string) bool {
	for _, role := range m.roles {
		if role == r {
			return true
		}
	}
	return false
}

// Mock user provider
type mockUserProvider struct {
	users       map[string]*mockUser
	apiKeyUsers map[string]*mockUser
	idUsers     map[uuid.UUID]*mockUser
}

func newMockUserProvider() *mockUserProvider {
	return &mockUserProvider{
		users:       make(map[string]*mockUser),
		apiKeyUsers: make(map[string]*mockUser),
		idUsers:     make(map[uuid.UUID]*mockUser),
	}
}

func (m *mockUserProvider) ProvideByUserPass(username, password string) (model.User, error) {
	key := username + ":" + password
	if user, ok := m.users[key]; ok {
		return user, nil
	}
	return nil, nil
}

func (m *mockUserProvider) ProvideByID(id uuid.UUID) (model.User, error) {
	if user, ok := m.idUsers[id]; ok {
		return user, nil
	}
	return nil, nil
}

func (m *mockUserProvider) ProvideByApiKey(apiKey string) (model.User, error) {
	if user, ok := m.apiKeyUsers[apiKey]; ok {
		return user, nil
	}
	return nil, nil
}

func (m *mockUserProvider) addUser(username, password string, user *mockUser) {
	m.users[username+":"+password] = user
	m.idUsers[user.id] = user
}

func (m *mockUserProvider) addApiKeyUser(apiKey string, user *mockUser) {
	m.apiKeyUsers[apiKey] = user
	m.idUsers[user.id] = user
}

func init() {
	gin.SetMode(gin.TestMode)
}

// --- AuthenticationMethod Tests ---

func TestAuthenticationMethodConstants(t *testing.T) {
	if AuthenticationMethodBearer != 0 {
		t.Errorf("expected AuthenticationMethodBearer=0, got %d", AuthenticationMethodBearer)
	}
	if AuthenticationMethodBasic != 1 {
		t.Errorf("expected AuthenticationMethodBasic=1, got %d", AuthenticationMethodBasic)
	}
	if AuthenticationMethodApiKey != 2 {
		t.Errorf("expected AuthenticationMethodApiKey=2, got %d", AuthenticationMethodApiKey)
	}
	if AuthenticationMethodBearerOAuth2 != 3 {
		t.Errorf("expected AuthenticationMethodBearerOAuth2=3, got %d", AuthenticationMethodBearerOAuth2)
	}
}

// --- BearerAuthenticator Tests ---

func TestBearerAuthenticator_Method(t *testing.T) {
	provider := newMockUserProvider()
	auth := NewBearerAuthenticator(provider, "secret")

	if auth.Method() != AuthenticationMethodBearer {
		t.Errorf("expected Bearer method, got %d", auth.Method())
	}
}

func TestBearerAuthenticator_Authenticate_NoHeader(t *testing.T) {
	provider := newMockUserProvider()
	auth := NewBearerAuthenticator(provider, "secret")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	user, err := auth.Authenticate(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user != nil {
		t.Error("expected nil user when no auth header")
	}
}

func TestBearerAuthenticator_Authenticate_InvalidHeader(t *testing.T) {
	provider := newMockUserProvider()
	auth := NewBearerAuthenticator(provider, "secret")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	user, err := auth.Authenticate(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user != nil {
		t.Error("expected nil user for non-Bearer auth")
	}
}

func TestBearerAuthenticator_Authenticate_ValidToken(t *testing.T) {
	provider := newMockUserProvider()
	testUser := &mockUser{id: uuid.New(), roles: []string{"user"}}
	provider.addUser("test", "pass", testUser)

	auth := NewBearerAuthenticator(provider, "secret")

	// Create a valid token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": testUser.id.String(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	tokenString, _ := token.SignedString([]byte("secret"))

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Bearer "+tokenString)

	user, err := auth.Authenticate(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.ID() != testUser.id {
		t.Errorf("expected user ID %s, got %s", testUser.id, user.ID())
	}
}

func TestBearerAuthenticator_SetExp(t *testing.T) {
	provider := newMockUserProvider()
	auth := NewBearerAuthenticator(provider, "secret")

	auth.SetExp(3600)
	// No direct way to verify, but should not panic
}

// --- BasicAuthenticator Tests ---

func TestBasicAuthenticator_Method(t *testing.T) {
	provider := newMockUserProvider()
	auth := NewBasicAuthenticator(provider)

	if auth.Method() != AuthenticationMethodBasic {
		t.Errorf("expected Basic method, got %d", auth.Method())
	}
}

func TestBasicAuthenticator_Authenticate_NoHeader(t *testing.T) {
	provider := newMockUserProvider()
	auth := NewBasicAuthenticator(provider)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	user, err := auth.Authenticate(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user != nil {
		t.Error("expected nil user when no auth header")
	}
}

func TestBasicAuthenticator_Authenticate_ValidCredentials(t *testing.T) {
	provider := newMockUserProvider()
	testUser := &mockUser{id: uuid.New(), roles: []string{"user"}}
	provider.addUser("testuser", "testpass", testUser)

	auth := NewBasicAuthenticator(provider)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.SetBasicAuth("testuser", "testpass")

	user, err := auth.Authenticate(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.ID() != testUser.id {
		t.Errorf("expected user ID %s, got %s", testUser.id, user.ID())
	}
}

func TestBasicAuthenticator_Authenticate_InvalidCredentials(t *testing.T) {
	provider := newMockUserProvider()
	auth := NewBasicAuthenticator(provider)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.SetBasicAuth("wrong", "creds")

	user, err := auth.Authenticate(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user != nil {
		t.Error("expected nil user for invalid credentials")
	}
}

// --- ApiKeyAuthenticator Tests ---

func TestApiKeyAuthenticator_Method(t *testing.T) {
	provider := newMockUserProvider()
	auth := NewApiKeyAuthenticator(provider)

	if auth.Method() != AuthenticationMethodApiKey {
		t.Errorf("expected ApiKey method, got %d", auth.Method())
	}
}

func TestApiKeyAuthenticator_Authenticate_NoHeader(t *testing.T) {
	provider := newMockUserProvider()
	auth := NewApiKeyAuthenticator(provider)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	user, err := auth.Authenticate(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user != nil {
		t.Error("expected nil user when no API key header")
	}
}

func TestApiKeyAuthenticator_Authenticate_ValidKey(t *testing.T) {
	provider := newMockUserProvider()
	testUser := &mockUser{id: uuid.New(), roles: []string{"api"}}
	provider.addApiKeyUser("test-api-key-123", testUser)

	auth := NewApiKeyAuthenticator(provider)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("X-API-Key", "test-api-key-123")

	user, err := auth.Authenticate(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.ID() != testUser.id {
		t.Errorf("expected user ID %s, got %s", testUser.id, user.ID())
	}
}

func TestApiKeyAuthenticator_Authenticate_InvalidKey(t *testing.T) {
	provider := newMockUserProvider()
	auth := NewApiKeyAuthenticator(provider)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("X-API-Key", "invalid-key")

	user, err := auth.Authenticate(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if user != nil {
		t.Error("expected nil user for invalid API key")
	}
}

// --- StateMap Tests ---

func TestStateMap_Generate(t *testing.T) {
	sm := NewStateMap()

	state := sm.Generate(5)
	if state == "" {
		t.Error("expected non-empty state")
	}

	// Should be a valid UUID
	if _, err := uuid.Parse(state); err != nil {
		t.Errorf("expected valid UUID, got %s", state)
	}
}

func TestStateMap_Validate(t *testing.T) {
	sm := NewStateMap()

	state := sm.Generate(5)

	if !sm.Validate(state) {
		t.Error("expected Validate to return true for generated state")
	}

	if sm.Validate("nonexistent") {
		t.Error("expected Validate to return false for nonexistent state")
	}
}

func TestStateMap_ValidateOnce(t *testing.T) {
	sm := NewStateMap()

	state := sm.Generate(5)

	if !sm.ValidateOnce(state) {
		t.Error("expected ValidateOnce to return true first time")
	}

	if sm.ValidateOnce(state) {
		t.Error("expected ValidateOnce to return false second time (state consumed)")
	}
}

// --- StringStateMap Tests ---

func TestStringStateMap_StoreAndPop(t *testing.T) {
	ssm := NewStringStateMap()

	ssm.Store("key1", "value1", 5)

	val := ssm.Pop("key1")
	if val != "value1" {
		t.Errorf("expected value1, got %s", val)
	}

	// Should be removed after Pop
	val = ssm.Pop("key1")
	if val != "" {
		t.Errorf("expected empty string after second Pop, got %s", val)
	}
}

func TestStringStateMap_PopNonexistent(t *testing.T) {
	ssm := NewStringStateMap()

	val := ssm.Pop("nonexistent")
	if val != "" {
		t.Errorf("expected empty string for nonexistent key, got %s", val)
	}
}

// --- PKCE Tests ---

func TestGeneratePKCE(t *testing.T) {
	verifier, challenge := GeneratePKCE()

	if len(verifier) == 0 {
		t.Error("expected non-empty verifier")
	}

	if len(challenge) == 0 {
		t.Error("expected non-empty challenge")
	}

	// Verify S256 challenge is correct
	sum := sha256.Sum256([]byte(verifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if challenge != expectedChallenge {
		t.Errorf("challenge mismatch: expected %s, got %s", expectedChallenge, challenge)
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce := GenerateNonce()

	if len(nonce) == 0 {
		t.Error("expected non-empty nonce")
	}

	// Should be base64url encoded
	if strings.ContainsAny(nonce, "+/=") {
		t.Error("nonce should be base64url encoded (no +, /, =)")
	}
}

func TestGeneratePKCE_Uniqueness(t *testing.T) {
	verifiers := make(map[string]bool)

	for i := 0; i < 100; i++ {
		verifier, _ := GeneratePKCE()
		if verifiers[verifier] {
			t.Error("generated duplicate verifier")
		}
		verifiers[verifier] = true
	}
}

// --- OIDC Mock Server Tests ---

func TestValidateIDTokenWithIssuer_MockServer(t *testing.T) {
	// Generate RSA key pair for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	var server *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":   server.URL,
			"jwks_uri": server.URL + "/jwks",
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Encode public key as JWK
		n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}) // 65537

		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{
				{
					"kty": "RSA",
					"kid": "test-key-id",
					"use": "sig",
					"alg": "RS256",
					"n":   n,
					"e":   e,
				},
			},
		})
	})

	server = httptest.NewServer(mux)
	defer server.Close()

	// Create a valid ID token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   server.URL,
		"aud":   "test-client-id",
		"sub":   "user123",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": "test-nonce",
	})
	token.Header["kid"] = "test-key-id"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// Validate the token
	err = ValidateIDTokenWithIssuer(tokenString, server.URL, "test-client-id", "test-nonce")
	if err != nil {
		t.Errorf("expected valid token, got error: %v", err)
	}
}

func TestValidateIDTokenWithIssuer_InvalidNonce(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	var server *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":   server.URL,
			"jwks_uri": server.URL + "/jwks",
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{
				{"kty": "RSA", "kid": "test-key-id", "use": "sig", "alg": "RS256", "n": n, "e": e},
			},
		})
	})

	server = httptest.NewServer(mux)
	defer server.Close()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   server.URL,
		"aud":   "test-client-id",
		"sub":   "user123",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": "wrong-nonce",
	})
	token.Header["kid"] = "test-key-id"

	tokenString, _ := token.SignedString(privateKey)

	err := ValidateIDTokenWithIssuer(tokenString, server.URL, "test-client-id", "expected-nonce")
	if err == nil {
		t.Error("expected error for nonce mismatch")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("expected nonce error, got: %v", err)
	}
}
