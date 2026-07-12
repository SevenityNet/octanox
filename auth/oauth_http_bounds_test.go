package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// --- bounded client construction ---

type markerTransport struct{ http.RoundTripper }

func TestBoundedHTTPClient_PreservesBaseTransport(t *testing.T) {
	rt := &markerTransport{http.DefaultTransport}
	base := &http.Client{Transport: rt}
	got := boundedHTTPClient(base, 0)
	if got.Transport != rt {
		t.Fatal("bounded client dropped the base transport")
	}
	if got.Timeout != defaultOAuthHTTPTimeout {
		t.Fatalf("expected default timeout, got %v", got.Timeout)
	}
}

func TestBoundedHTTPClient_PreservesDefaultClientTransport(t *testing.T) {
	rt := &markerTransport{http.DefaultTransport}
	orig := http.DefaultClient.Transport
	http.DefaultClient.Transport = rt
	defer func() { http.DefaultClient.Transport = orig }()

	got := boundedHTTPClient(nil, 5*time.Second)
	if got.Transport != rt {
		t.Fatal("nil-base bounded client ignored http.DefaultClient's custom transport")
	}
	if got.Timeout != 5*time.Second {
		t.Fatalf("expected 5s timeout, got %v", got.Timeout)
	}
}

// --- OIDC fetch bounding ---

func TestValidateIDTokenWithIssuer_DiscoveryTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	start := time.Now()
	err := validateIDTokenWithIssuer(context.Background(), boundedHTTPClient(nil, 50*time.Millisecond), "tok", server.URL, "client", "")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("expected abort near the 50ms deadline, took %v", time.Since(start))
	}
}

func TestValidateIDTokenWithIssuer_JWKSTimeout(t *testing.T) {
	release := make(chan struct{})
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": server.URL, "jwks_uri": server.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { <-release })
	server = httptest.NewServer(mux)
	defer server.Close()
	defer close(release)

	start := time.Now()
	err := validateIDTokenWithIssuer(context.Background(), boundedHTTPClient(nil, 50*time.Millisecond), "tok", server.URL, "client", "")
	if err == nil {
		t.Fatal("expected JWKS timeout error, got nil")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("expected abort near the 50ms deadline, took %v", time.Since(start))
	}
}

func TestFetchJSONBounded_BodyCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"issuer":"x","jwks_uri":"`)
		filler := make([]byte, oidcMaxResponseBytes+1024)
		for i := range filler {
			filler[i] = 'a'
		}
		w.Write(filler)
		fmt.Fprint(w, `"}`)
	}))
	defer server.Close()

	var disc oidcDiscovery
	err := fetchJSONBounded(context.Background(), boundedHTTPClient(nil, 0), server.URL, &disc)
	if err == nil {
		t.Fatal("expected oversized-body error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds size limit") {
		t.Fatalf("expected explicit size-limit error, got: %v", err)
	}
}

func TestValidateIDTokenWithIssuer_NearCapAndOversizedJWKS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	newServer := func(jwksPadding int) *httptest.Server {
		var server *httptest.Server
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"issuer": server.URL, "jwks_uri": server.URL + "/jwks"})
		})
		mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
			n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
			payload := map[string]any{
				"padding": strings.Repeat("a", jwksPadding),
				"keys": []map[string]string{
					{"kty": "RSA", "kid": "k", "use": "sig", "alg": "RS256", "n": n, "e": e},
				},
			}
			json.NewEncoder(w).Encode(payload)
		})
		server = httptest.NewServer(mux)
		return server
	}

	mkToken := func(iss string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": iss, "aud": "cid", "sub": "u", "exp": time.Now().Add(time.Hour).Unix(),
		})
		tok.Header["kid"] = "k"
		s, _ := tok.SignedString(privateKey)
		return s
	}

	t.Run("near cap succeeds", func(t *testing.T) {
		server := newServer(oidcMaxResponseBytes - 4096)
		defer server.Close()
		if err := validateIDTokenWithIssuer(context.Background(), boundedHTTPClient(nil, 0), mkToken(server.URL), server.URL, "cid", ""); err != nil {
			t.Fatalf("expected near-cap JWKS to validate, got: %v", err)
		}
	})

	t.Run("oversized rejected", func(t *testing.T) {
		server := newServer(oidcMaxResponseBytes + 4096)
		defer server.Close()
		err := validateIDTokenWithIssuer(context.Background(), boundedHTTPClient(nil, 0), mkToken(server.URL), server.URL, "cid", "")
		if err == nil || !strings.Contains(err.Error(), "exceeds size limit") {
			t.Fatalf("expected oversized-JWKS size-limit error, got: %v", err)
		}
	})
}

// --- token exchange bounding through the callback path ---

func newCallbackAuth(t *testing.T, tokenURL string, timeout time.Duration) (*OAuth2BearerAuthenticator, string) {
	t.Helper()
	a := NewOAuth2BearerAuthenticator(OAuth2Config{Secret: "test-secret", ClientID: "cid", ClientSecret: "sec"})
	a.config.Endpoint = oauth2.Endpoint{AuthURL: tokenURL, TokenURL: tokenURL}
	if timeout != 0 {
		a.SetHTTPTimeout(timeout)
	}
	state := "state123"
	ctx := context.Background()
	a.stateStore.Set(ctx, "s:"+state, "1", time.Minute)
	a.stateStore.Set(ctx, "p:"+state, "verifier", time.Minute)
	a.stateStore.Set(ctx, "n:"+state, "nonce", time.Minute)
	return a, state
}

func TestCallback_TokenExchangeTimeout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer server.Close()
	defer close(release)

	a, state := newCallbackAuth(t, server.URL, 50*time.Millisecond)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/oauth2/callback?state="+state+"&code=abc", nil)

	start := time.Now()
	a.callback(c)
	if time.Since(start) > 2*time.Second {
		t.Fatalf("expected exchange to abort near the 50ms timeout, took %v", time.Since(start))
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "token_exchange_failed") {
		t.Fatalf("expected token_exchange_failed redirect, got %q", loc)
	}
}

func TestCallback_TokenExchangeCanceledContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer server.Close()
	defer close(release)

	a, state := newCallbackAuth(t, server.URL, 0) // default 10s timeout; cancellation must win
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	reqCtx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Request = httptest.NewRequest("GET", "/oauth2/callback?state="+state+"&code=abc", nil).WithContext(reqCtx)

	start := time.Now()
	a.callback(c)
	if time.Since(start) > 2*time.Second {
		t.Fatalf("expected canceled request context to abort exchange fast, took %v", time.Since(start))
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "token_exchange_failed") {
		t.Fatalf("expected token_exchange_failed redirect, got %q", loc)
	}
}

func TestCallback_DefaultTimeoutPropagates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a, _ := newCallbackAuth(t, "http://127.0.0.1:0", 0)
	if a.effectiveTimeout() != defaultOAuthHTTPTimeout {
		t.Fatalf("expected default %v, got %v", defaultOAuthHTTPTimeout, a.effectiveTimeout())
	}
	a.SetHTTPTimeout(3 * time.Second)
	if a.effectiveTimeout() != 3*time.Second {
		t.Fatalf("expected 3s after SetHTTPTimeout, got %v", a.effectiveTimeout())
	}
}

// --- logout ordering (cookie deletion queued before the hook) ---

func TestLogout_CookieClearedBeforeResponseWritingHook(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := NewOAuth2BearerAuthenticator(OAuth2Config{Secret: "test-secret"})
	a.EnableCookieAuth("octanox_token", "", false)

	var hookRan bool
	a.OnLogout(func(c *gin.Context) {
		hookRan = true
		c.String(200, "hook wrote this") // commits headers mid-logout
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/logout", nil)
	a.logout(c)

	if !hookRan {
		t.Fatal("OnLogout hook did not run")
	}
	var cleared bool
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "octanox_token" && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("deletion cookie lost when hook wrote a response before it")
	}
}
