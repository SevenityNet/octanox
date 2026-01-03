package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
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

func TestCORS_SpecificOrigin(t *testing.T) {
	os.Setenv("NOX__CORS_ALLOWED_ORIGINS", "https://allowed.com")
	defer os.Unsetenv("NOX__CORS_ALLOWED_ORIGINS")

	cors := CORS()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("Origin", "https://other.com")

	cors(c)

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "https://allowed.com" {
		t.Errorf("expected origin https://allowed.com, got %s", origin)
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
