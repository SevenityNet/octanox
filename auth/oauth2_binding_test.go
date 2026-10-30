package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sevenitynet/octanox/model"
	"golang.org/x/oauth2"
)

type idTokenProvider struct {
	mockOAuth2Provider
	gotAccess string
	gotClaims map[string]any
}

func (p *idTokenProvider) ProvideForLoginWithIDToken(access string, claims map[string]any) (model.User, error) {
	p.gotAccess, p.gotClaims = access, claims
	return p.user, nil
}

func (p *idTokenProvider) ProvideForLogin(string) (model.User, error) {
	panic("ProvideForLogin must not be called when the ID-token interface is implemented")
}

// oidcServer serves discovery, JWKS and a token endpoint returning an ID token for subject sub.
func oidcServer(t *testing.T, sub string, nonce *string) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": srv.URL, "aud": "cid", "sub": sub, "nonce": *nonce, "exp": time.Now().Add(time.Hour).Unix(),
		})
		tok.Header["kid"] = "k"
		signed, _ := tok.SignedString(key)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "bearer", "expires_in": 3600, "id_token": signed})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func callbackRequest(state string, cookie *http.Cookie) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback?state="+url.QueryEscape(state)+"&code=c", nil)
	if cookie != nil {
		c.Request.AddCookie(cookie)
	}
	return c
}

func TestOAuth2_Callback_PassesIDTokenClaims(t *testing.T) {
	nonce := "n-1"
	srv := oidcServer(t, "idp-subject-1", &nonce)
	prov := &idTokenProvider{mockOAuth2Provider: mockOAuth2Provider{user: &mockUser{id: uuid.New()}}}
	a := NewOAuth2BearerAuthenticator(OAuth2Config{Provider: prov, Endpoint: oauth2.Endpoint{AuthURL: srv.URL, TokenURL: srv.URL + "/token"},
		ClientID: "cid", Secret: "test-secret", LoginSuccessRedirect: "/"})
	a.EnableOIDCValidation(srv.URL)
	ctx := context.Background()
	_ = a.stateStore.Set(ctx, "s:st", "1", time.Minute)
	_ = a.stateStore.Set(ctx, "p:st", "v", time.Minute)
	_ = a.stateStore.Set(ctx, "n:st", nonce, time.Minute)

	c := callbackRequest("st", nil)
	a.callback(c)
	if loc := c.Writer.Header().Get("Location"); parseQueryParam(t, loc, "token") == "" {
		t.Fatalf("expected a token, got redirect %q", loc)
	}
	if prov.gotAccess != "at" || prov.gotClaims["sub"] != "idp-subject-1" {
		t.Fatalf("provider got access %q claims %v", prov.gotAccess, prov.gotClaims)
	}
}

func TestOAuth2_StateCookieBinding(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a, _, cleanup := oauthCallbackAuth(t)
	defer cleanup()
	a.config.RedirectURL = "https://app.example/auth/oauth2/callback"
	a.EnableStateCookie()
	r := gin.New()
	a.RegisterRoutes(r.Group("/auth"))

	login := func() (string, *http.Cookie) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
		loc, _ := url.Parse(w.Header().Get("Location"))
		for _, ck := range w.Result().Cookies() {
			if ck.Name == stateCookieName {
				if ck.Path != "/auth/oauth2/callback" || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode {
					t.Fatalf("state cookie attributes: %+v", ck)
				}
				return loc.Query().Get("state"), ck
			}
		}
		t.Fatal("login set no state cookie")
		return "", nil
	}
	run := func(state string, ck *http.Cookie) string {
		c := callbackRequest(state, ck)
		a.callback(c)
		return c.Writer.Header().Get("Location")
	}

	state, ck := login()
	if loc := run(state, ck); parseQueryParam(t, loc, "token") == "" {
		t.Fatalf("bound callback failed: %q", loc)
	}

	state, _ = login()
	if loc := run(state, nil); !strings.Contains(loc, "invalid_state") {
		t.Fatalf("callback without cookie must fail, got %q", loc)
	}
	if loc := run(state, ck); !strings.Contains(loc, "invalid_state") {
		t.Fatalf("state must be consumed by the failed attempt, got %q", loc)
	}

	state, _ = login()
	_, other := login()
	if loc := run(state, other); !strings.Contains(loc, "invalid_state") {
		t.Fatalf("callback with another login's cookie must fail, got %q", loc)
	}
}
