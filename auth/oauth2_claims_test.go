package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sevenitynet/octanox/model"
	"golang.org/x/oauth2"
)

// mockClaimsProvider implements OAuth2UserProvider plus the optional OAuth2ClaimsUserProvider.
type mockClaimsProvider struct {
	user       *mockUser
	gotClaims  map[string]any
	byIDCalled bool
	rejectErr  error
}

func (m *mockClaimsProvider) ProvideForLogin(string) (model.User, error) { return m.user, nil }

func (m *mockClaimsProvider) ProvideByID(uuid.UUID) (model.User, error) {
	m.byIDCalled = true
	return m.user, nil
}

func (m *mockClaimsProvider) ProvideByIDWithClaims(_ uuid.UUID, claims map[string]any) (model.User, error) {
	m.gotClaims = claims
	if m.rejectErr != nil {
		return nil, m.rejectErr
	}
	return m.user, nil
}

func newTestOAuth2(provider OAuth2UserProvider) *OAuth2BearerAuthenticator {
	return NewOAuth2BearerAuthenticator(OAuth2Config{Provider: provider, Secret: "test-secret"})
}

func bearerContext(token string) *gin.Context {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)
	return c
}

func TestOAuth2_OnLogin_ClaimsMergedAndReservedProtected(t *testing.T) {
	user := &mockUser{id: uuid.New()}
	a := newTestOAuth2(&mockOAuth2Provider{user: user})

	sid := uuid.New().String()
	a.OnLogin(func(_ *gin.Context, _ model.User) (map[string]any, error) {
		return map[string]any{"sid": sid, "sub": "attacker"}, nil
	})

	claims, err := a.onLogin(nil, user)
	if err != nil {
		t.Fatalf("hook returned error: %v", err)
	}
	token, err := a.createToken(user, claims)
	if err != nil {
		t.Fatalf("createToken failed: %v", err)
	}

	subject, parsed := a.extractToken(token)
	if subject == nil || *subject != user.id {
		t.Fatal("reserved sub claim must not be overridable by hook claims")
	}
	if parsed["sid"] != sid {
		t.Errorf("expected sid claim %q, got %v", sid, parsed["sid"])
	}
}

func TestOAuth2_CreateToken_ReservedClaimsNotOverridable(t *testing.T) {
	user := &mockUser{id: uuid.New()}
	a := newTestOAuth2(&mockOAuth2Provider{user: user})

	for _, key := range []string{"iss", "aud", "sub", "exp", "iat", "nbf", "jti"} {
		sentinel := "HACKED-" + key
		token, err := a.createToken(user, map[string]any{key: sentinel})
		if err != nil {
			t.Fatalf("createToken failed for %q: %v", key, err)
		}
		subject, claims := a.extractToken(token)
		if claims[key] == sentinel {
			t.Errorf("reserved claim %q was overridden by hook value", key)
		}
		if subject == nil || *subject != user.id {
			t.Errorf("reserved sub claim corrupted while testing %q", key)
		}
	}
}

// oauthCallbackAuth wires an authenticator whose token endpoint is a local stub, so callback() runs end-to-end.
func oauthCallbackAuth(t *testing.T) (*OAuth2BearerAuthenticator, *mockUser, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"bearer","expires_in":3600}`))
	}))
	user := &mockUser{id: uuid.New()}
	a := NewOAuth2BearerAuthenticator(OAuth2Config{
		Provider:             &mockOAuth2Provider{user: user},
		Endpoint:             oauth2.Endpoint{AuthURL: srv.URL, TokenURL: srv.URL},
		Secret:               "test-secret",
		LoginSuccessRedirect: "https://app.example/done",
	})
	return a, user, srv.Close
}

func runCallback(t *testing.T, a *OAuth2BearerAuthenticator) string {
	t.Helper()
	const state = "test-state"
	ctx := context.Background()
	_ = a.stateStore.Set(ctx, "s:"+state, "1", time.Minute)
	_ = a.stateStore.Set(ctx, "p:"+state, "test-verifier", time.Minute)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth2/callback?state="+state+"&code=test-code", nil)
	a.callback(c)
	return w.Header().Get("Location")
}

func TestOAuth2_Callback_HookInvokedAndClaimsIssued(t *testing.T) {
	a, user, cleanup := oauthCallbackAuth(t)
	defer cleanup()

	invoked := false
	a.OnLogin(func(_ *gin.Context, u model.User) (map[string]any, error) {
		invoked = true
		if u.ID() != user.id {
			t.Errorf("hook received wrong user")
		}
		return map[string]any{"sid": "sess-9"}, nil
	})

	loc := runCallback(t, a)
	if !invoked {
		t.Fatal("login hook was not invoked during callback")
	}

	token := parseQueryParam(t, loc, "token")
	if token == "" {
		t.Fatalf("expected token in redirect, got %q", loc)
	}
	subject, claims := a.extractToken(token)
	if subject == nil || *subject != user.id {
		t.Fatal("issued token has wrong subject")
	}
	if claims["sid"] != "sess-9" {
		t.Errorf("expected sid claim in issued token, got %v", claims["sid"])
	}
}

func TestOAuth2_Callback_HookErrorAbortsLogin(t *testing.T) {
	a, _, cleanup := oauthCallbackAuth(t)
	defer cleanup()

	a.OnLogin(func(_ *gin.Context, _ model.User) (map[string]any, error) {
		return nil, errors.New("session creation failed")
	})

	loc := runCallback(t, a)
	if !strings.Contains(loc, "login_hook_failed") {
		t.Errorf("expected login_hook_failed redirect, got %q", loc)
	}
	if parseQueryParam(t, loc, "token") != "" {
		t.Error("no token should be issued when the hook errors")
	}
}

func TestOAuth2_Callback_UnserializableClaimAbortsCleanly(t *testing.T) {
	a, _, cleanup := oauthCallbackAuth(t)
	defer cleanup()

	a.OnLogin(func(_ *gin.Context, _ model.User) (map[string]any, error) {
		return map[string]any{"bad": make(chan int)}, nil
	})

	loc := runCallback(t, a)
	if !strings.Contains(loc, "token_creation_failed") {
		t.Errorf("expected token_creation_failed redirect (not a panic), got %q", loc)
	}
	if parseQueryParam(t, loc, "token") != "" {
		t.Error("no token should be issued when claims are unserializable")
	}
}

func parseQueryParam(t *testing.T, rawURL, key string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("bad redirect URL %q: %v", rawURL, err)
	}
	return u.Query().Get(key)
}

func TestOAuth2_Authenticate_ClaimsAwareProvider(t *testing.T) {
	user := &mockUser{id: uuid.New()}
	prov := &mockClaimsProvider{user: user}
	a := newTestOAuth2(prov)

	token, err := a.createToken(user, map[string]any{"sid": "session-1"})
	if err != nil {
		t.Fatalf("createToken failed: %v", err)
	}

	got, err := a.Authenticate(bearerContext(token))
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if got == nil || got.ID() != user.id {
		t.Fatal("expected authenticated user")
	}
	if prov.byIDCalled {
		t.Error("ProvideByID must not be called when the claims-aware interface is implemented")
	}
	if prov.gotClaims["sid"] != "session-1" {
		t.Errorf("expected sid claim forwarded to provider, got %v", prov.gotClaims["sid"])
	}
}

func TestOAuth2_Authenticate_ClaimsAwareRejection(t *testing.T) {
	user := &mockUser{id: uuid.New()}
	prov := &mockClaimsProvider{user: user, rejectErr: errors.New("session revoked")}
	a := newTestOAuth2(prov)

	token, _ := a.createToken(user, map[string]any{"sid": "stale"})

	got, err := a.Authenticate(bearerContext(token))
	if err == nil {
		t.Fatal("expected error when claims validation rejects the request")
	}
	if got != nil {
		t.Error("expected no user when claims validation fails")
	}
}

func TestOAuth2_Authenticate_LegacyProviderFallback(t *testing.T) {
	user := &mockUser{id: uuid.New()}
	prov := &mockOAuth2Provider{user: user}
	a := newTestOAuth2(prov)

	token, _ := a.createToken(user, nil)

	got, err := a.Authenticate(bearerContext(token))
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if got == nil || got.ID() != user.id {
		t.Fatal("expected legacy provider to resolve the user via ProvideByID")
	}
}
