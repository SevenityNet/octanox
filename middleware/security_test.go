package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// --- CSPConfig.Build Tests ---

func TestCSPConfig_Build_Default(t *testing.T) {
	cfg := DefaultAPICSP()
	got := cfg.Build()
	want := "default-src 'none'; frame-ancestors 'none'"
	if got != want {
		t.Errorf("DefaultAPICSP().Build() = %q, want %q", got, want)
	}
}

func TestCSPConfig_Build_MultipleDirectives(t *testing.T) {
	cfg := CSPConfig{
		DefaultSrc: []string{"'self'"},
		ScriptSrc:  []string{"'self'", "https://cdn.example.com"},
		StyleSrc:   []string{"'self'", "'unsafe-inline'"},
		ImgSrc:     []string{"'self'", "data:", "https:"},
	}
	got := cfg.Build()
	want := "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:"
	if got != want {
		t.Errorf("Build() = %q, want %q", got, want)
	}
}

func TestCSPConfig_Build_EmptyDirectivesOmitted(t *testing.T) {
	cfg := CSPConfig{
		DefaultSrc: []string{"'none'"},
		ScriptSrc:  nil,
		StyleSrc:   []string{},
		ImgSrc:     []string{"'self'"},
	}
	got := cfg.Build()
	want := "default-src 'none'; img-src 'self'"
	if got != want {
		t.Errorf("Build() = %q, want %q", got, want)
	}
}

func TestCSPConfig_Build_AllDirectives(t *testing.T) {
	cfg := CSPConfig{
		DefaultSrc:     []string{"'self'"},
		ScriptSrc:      []string{"'self'"},
		StyleSrc:       []string{"'self'"},
		ImgSrc:         []string{"'self'"},
		FontSrc:        []string{"'self'"},
		ConnectSrc:     []string{"'self'"},
		FrameSrc:       []string{"'none'"},
		WorkerSrc:      []string{"'self'"},
		ObjectSrc:      []string{"'none'"},
		BaseURI:        []string{"'self'"},
		FormAction:     []string{"'self'"},
		FrameAncestors: []string{"'none'"},
	}
	got := cfg.Build()
	want := "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'none'; worker-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
	if got != want {
		t.Errorf("Build() = %q, want %q", got, want)
	}
}

func TestCSPConfig_Build_Empty(t *testing.T) {
	cfg := CSPConfig{}
	got := cfg.Build()
	if got != "" {
		t.Errorf("empty CSPConfig.Build() = %q, want empty string", got)
	}
}

// --- SwaggerCSP Middleware Tests ---

func TestSwaggerCSP_SetsPermissivePolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := SwaggerCSP()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/docs/index.html", nil)

	handler(c)

	got := w.Header().Get("Content-Security-Policy")
	want := "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'"
	if got != want {
		t.Errorf("SwaggerCSP() Content-Security-Policy = %q, want %q", got, want)
	}
}

func TestSwaggerCSP_OverridesStrictPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	_, engine := gin.CreateTestContext(w)

	// Global strict CSP applied first, then SwaggerCSP overrides on the route
	engine.Use(SecurityHeaders())
	engine.GET("/docs/*any", SwaggerCSP(), func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/docs/index.html", nil)
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	got := w.Header().Get("Content-Security-Policy")
	// The route-level SwaggerCSP should win because it runs after the global middleware
	want := "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'"
	if got != want {
		t.Errorf("SwaggerCSP override: Content-Security-Policy = %q, want %q", got, want)
	}
}

// --- SecurityHeaders Middleware Tests ---

func TestSecurityHeaders_DefaultPolicy(t *testing.T) {
	handler := SecurityHeaders()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler(c)

	got := w.Header().Get("Content-Security-Policy")
	want := "default-src 'none'; frame-ancestors 'none'"
	if got != want {
		t.Errorf("Content-Security-Policy = %q, want %q", got, want)
	}
}

func TestSecurityHeaders_CustomConfig(t *testing.T) {
	cfg := CSPConfig{
		DefaultSrc: []string{"'self'"},
		ScriptSrc:  []string{"'self'", "https://cdn.example.com"},
	}
	handler := SecurityHeaders(cfg)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler(c)

	got := w.Header().Get("Content-Security-Policy")
	want := "default-src 'self'; script-src 'self' https://cdn.example.com"
	if got != want {
		t.Errorf("Content-Security-Policy = %q, want %q", got, want)
	}
}

func TestSecurityHeaders_EnvOverride(t *testing.T) {
	t.Setenv("NOX__CSP_POLICY", "default-src 'self'; script-src 'unsafe-inline'")

	handler := SecurityHeaders()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler(c)

	got := w.Header().Get("Content-Security-Policy")
	want := "default-src 'self'; script-src 'unsafe-inline'"
	if got != want {
		t.Errorf("Content-Security-Policy = %q, want %q", got, want)
	}
}

func TestSecurityHeaders_ReportOnly(t *testing.T) {
	cfg := CSPConfig{
		DefaultSrc: []string{"'self'"},
		ReportOnly: true,
	}
	handler := SecurityHeaders(cfg)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler(c)

	// Should use Report-Only header
	got := w.Header().Get("Content-Security-Policy-Report-Only")
	if got == "" {
		t.Error("expected Content-Security-Policy-Report-Only header to be set")
	}

	// Should NOT set the standard CSP header
	standard := w.Header().Get("Content-Security-Policy")
	if standard != "" {
		t.Errorf("expected no Content-Security-Policy header, got %q", standard)
	}
}

func TestSecurityHeaders_ReportOnlyEnvOverride(t *testing.T) {
	t.Setenv("NOX__CSP_REPORT_ONLY", "true")

	handler := SecurityHeaders() // ReportOnly not set in config

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler(c)

	// Should use Report-Only header due to env var
	got := w.Header().Get("Content-Security-Policy-Report-Only")
	if got == "" {
		t.Error("expected Content-Security-Policy-Report-Only header when NOX__CSP_REPORT_ONLY=true")
	}

	standard := w.Header().Get("Content-Security-Policy")
	if standard != "" {
		t.Errorf("expected no Content-Security-Policy header, got %q", standard)
	}
}

func TestSecurityHeaders_SetsHeaderOnResponse(t *testing.T) {
	handler := SecurityHeaders()

	w := httptest.NewRecorder()
	c, engine := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	engine.GET("/test", handler, func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	engine.ServeHTTP(w, c.Request)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	got := w.Header().Get("Content-Security-Policy")
	if got == "" {
		t.Error("expected Content-Security-Policy header on response")
	}
}
