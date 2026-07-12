package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sevenitynet/octanox/errors"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func resetGlobals() {
	EmitErrorFunc = nil
}

// --- Logger Tests ---

func TestLogger(t *testing.T) {
	logger := Logger()
	if logger == nil {
		t.Error("expected non-nil logger middleware")
	}

	// Verify it's a valid handler
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	// Should not panic
	logger(c)
}

// --- CORS Tests ---

func TestCORS_AllowAll(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "*")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	cors := CORS()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("Origin", "https://example.com")

	cors(c)

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "https://example.com" {
		t.Errorf("expected origin https://example.com, got %s", origin)
	}

	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected Allow-Credentials: true")
	}
}

func TestCORS_AllowedOrigin(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "https://allowed.com")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	cors := CORS()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("Origin", "https://allowed.com")

	cors(c)

	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "https://allowed.com" {
		t.Errorf("expected echoed origin https://allowed.com, got %q", origin)
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected Allow-Credentials: true for allowed origin")
	}
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "https://allowed.com")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	cors := CORS()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("Origin", "https://other.com")

	cors(c)

	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "" {
		t.Errorf("expected no Allow-Origin for disallowed origin, got %q", origin)
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("expected no Allow-Credentials for disallowed origin")
	}
}

func TestCORS_MultipleOrigins(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "https://a.com, https://b.com ,https://c.com")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	cors := CORS()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("Origin", "https://b.com")

	cors(c)

	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "https://b.com" {
		t.Errorf("expected echoed origin https://b.com, got %q", origin)
	}
}

func TestCORS_WildcardWithCredentialsReflectsOrigin(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "*")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	cors := CORS()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("Origin", "https://example.com")

	cors(c)

	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "https://example.com" {
		t.Errorf("expected reflected origin https://example.com, got %q", origin)
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected Allow-Credentials: true with reflected wildcard origin")
	}
}

func TestCORS_VaryOriginAlwaysPresent(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "https://allowed.com")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	cors := CORS()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("Origin", "https://other.com")

	cors(c)

	if vary := w.Header().Get("Vary"); vary != "Origin" {
		t.Errorf("expected Vary: Origin even for disallowed origin, got %q", vary)
	}
}

func TestCORS_PreflightBeforeAuth(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "https://allowed.com")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	cors := CORS()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodOptions, "/test", nil)
	c.Request.Header.Set("Origin", "https://allowed.com")

	cors(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for preflight, got %d", w.Code)
	}
	if !c.IsAborted() {
		t.Error("expected preflight to abort before downstream handlers")
	}
	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "https://allowed.com" {
		t.Errorf("expected preflight to echo allowed origin, got %q", origin)
	}
}

func TestCORS_OptionsRequest(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "*")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	cors := CORS()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodOptions, "/test", nil)
	c.Request.Header.Set("Origin", "https://example.com")

	cors(c)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for OPTIONS, got %d", w.Code)
	}

	if !c.IsAborted() {
		t.Error("expected request to be aborted for OPTIONS")
	}
}

func TestCORS_Headers(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "*")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	cors := CORS()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	cors(c)

	methods := w.Header().Get("Access-Control-Allow-Methods")
	if methods == "" {
		t.Error("expected Allow-Methods header")
	}

	headers := w.Header().Get("Access-Control-Allow-Headers")
	if headers == "" {
		t.Error("expected Allow-Headers header")
	}

	expose := w.Header().Get("Access-Control-Expose-Headers")
	if expose == "" {
		t.Error("expected Expose-Headers header")
	}
}

func TestCORS_NegativeOrigins(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "https://allowed.com")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	cors := CORS()

	for _, origin := range []string{
		"http://allowed.com",       // scheme mismatch
		"https://allowed.com:8443", // port mismatch
		"https://allowed.com.evil", // suffix
		"https://evilallowed.com",  // substring/prefix
	} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
		c.Request.Header.Set("Origin", origin)

		cors(c)

		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin %q must not be allowed, got ACAO %q", origin, got)
		}
	}
}

func TestCORS_PreflightAbortsBeforeDownstream(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "https://allowed.com")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	downstreamRan := false
	engine := gin.New()
	engine.Use(CORS())
	engine.Use(func(c *gin.Context) { downstreamRan = true; c.AbortWithStatus(http.StatusUnauthorized) })
	engine.Any("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/x", nil)
	req.Header.Set("Origin", "https://allowed.com")
	engine.ServeHTTP(w, req)

	if downstreamRan {
		t.Error("downstream auth middleware ran during OPTIONS preflight")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for preflight, got %d", w.Code)
	}

	downstreamRan = false
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2.Header.Set("Origin", "https://allowed.com")
	engine.ServeHTTP(w2, req2)

	if !downstreamRan {
		t.Error("downstream middleware should run for a non-preflight request")
	}
}

func TestCORS_PreservesExistingVary(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "https://allowed.com")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	cors := CORS()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Writer.Header().Set("Vary", "Accept-Encoding")
	c.Request.Header.Set("Origin", "https://allowed.com")

	cors(c)

	vary := strings.Join(w.Header().Values("Vary"), ", ")
	if !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("pre-existing Vary value dropped, got %q", vary)
	}
	if !strings.Contains(vary, "Origin") {
		t.Errorf("Vary: Origin not added, got %q", vary)
	}
}

// --- Recovery Tests ---

func TestRecovery_NoPanic(t *testing.T) {
	resetGlobals()

	recovery := Recovery()

	w := httptest.NewRecorder()
	c, engine := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	engine.GET("/test", recovery, func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	engine.ServeHTTP(w, c.Request)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRecovery_FailedRequest(t *testing.T) {
	resetGlobals()

	recovery := Recovery()

	w := httptest.NewRecorder()
	c, engine := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	engine.GET("/test", recovery, func(c *gin.Context) {
		panic(errors.FailedRequest{Status: 400, Message: "bad request"})
	})

	engine.ServeHTTP(w, c.Request)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRecovery_GenericPanic(t *testing.T) {
	resetGlobals()

	var emittedError error
	EmitErrorFunc = func(err error) {
		emittedError = err
	}

	recovery := Recovery()

	w := httptest.NewRecorder()
	c, engine := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	engine.GET("/test", recovery, func(c *gin.Context) {
		panic("something went wrong")
	})

	engine.ServeHTTP(w, c.Request)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}

	if emittedError == nil {
		t.Error("expected error to be emitted")
	}
}

func TestRecovery_ErrorPanic(t *testing.T) {
	resetGlobals()

	var emittedError error
	EmitErrorFunc = func(err error) {
		emittedError = err
	}

	recovery := Recovery()

	w := httptest.NewRecorder()
	c, engine := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	engine.GET("/test", recovery, func(c *gin.Context) {
		panic(errors.FailedRequest{Status: 404, Message: "not found"})
	})

	engine.ServeHTTP(w, c.Request)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}

	// FailedRequest should not emit error
	if emittedError != nil {
		t.Error("expected no error emission for FailedRequest")
	}
}

// --- ErrorCollector Tests ---

func TestErrorCollector_NoErrors(t *testing.T) {
	resetGlobals()

	var emittedError error
	EmitErrorFunc = func(err error) {
		emittedError = err
	}

	collector := ErrorCollector()

	w := httptest.NewRecorder()
	c, engine := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	engine.GET("/test", collector, func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	engine.ServeHTTP(w, c.Request)

	if emittedError != nil {
		t.Error("expected no error emission when no errors")
	}
}

func TestErrorCollector_WithErrors(t *testing.T) {
	resetGlobals()

	var emittedError error
	EmitErrorFunc = func(err error) {
		emittedError = err
	}

	collector := ErrorCollector()

	w := httptest.NewRecorder()
	c, engine := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	engine.GET("/test", collector, func(c *gin.Context) {
		_ = c.Error(&gin.Error{Err: http.ErrAbortHandler, Type: gin.ErrorTypePrivate})
		c.JSON(200, gin.H{"status": "ok"})
	})

	engine.ServeHTTP(w, c.Request)

	if emittedError == nil {
		t.Error("expected error to be emitted")
	}
}

func TestErrorCollector_NoEmitFunc(t *testing.T) {
	resetGlobals()
	EmitErrorFunc = nil

	collector := ErrorCollector()

	w := httptest.NewRecorder()
	c, engine := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	engine.GET("/test", collector, func(c *gin.Context) {
		_ = c.Error(&gin.Error{Err: http.ErrAbortHandler, Type: gin.ErrorTypePrivate})
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Should not panic even without EmitErrorFunc
	engine.ServeHTTP(w, c.Request)
}
