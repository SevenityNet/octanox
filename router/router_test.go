package router

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sevenitynet/octanox/ctx"
	"github.com/sevenitynet/octanox/model"
	"github.com/sevenitynet/octanox/request"
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

func init() {
	gin.SetMode(gin.TestMode)
}

func resetGlobals() {
	IsDryRunFunc = nil
	AddRouteFunc = nil
	HasAuthenticatorFunc = nil
	AuthenticateFunc = nil
	SerializeFunc = nil
}

// --- Route Tests ---

func TestRoute_Struct(t *testing.T) {
	r := Route{
		Method:       http.MethodGet,
		Path:         "/test",
		RequestType:  reflect.TypeOf(request.GetRequest{}),
		ResponseType: reflect.TypeOf(struct{}{}),
	}

	if r.Method != http.MethodGet {
		t.Errorf("expected GET, got %s", r.Method)
	}
	if r.Path != "/test" {
		t.Errorf("expected /test, got %s", r.Path)
	}
}

// --- DetectHTTPMethod Tests ---

type getReq struct{ request.GetRequest }
type postReq struct{ request.PostRequest }
type putReq struct{ request.PutRequest }
type deleteReq struct{ request.DeleteRequest }
type patchReq struct{ request.PatchRequest }
type optionsReq struct{ request.OptionsRequest }
type headReq struct{ request.HeadRequest }
type traceReq struct{ request.TraceRequest }

func TestDetectHTTPMethod(t *testing.T) {
	tests := []struct {
		name     string
		reqType  reflect.Type
		expected string
	}{
		{"GET", reflect.TypeOf(getReq{}), http.MethodGet},
		{"POST", reflect.TypeOf(postReq{}), http.MethodPost},
		{"PUT", reflect.TypeOf(putReq{}), http.MethodPut},
		{"DELETE", reflect.TypeOf(deleteReq{}), http.MethodDelete},
		{"PATCH", reflect.TypeOf(patchReq{}), http.MethodPatch},
		{"OPTIONS", reflect.TypeOf(optionsReq{}), http.MethodOptions},
		{"HEAD", reflect.TypeOf(headReq{}), http.MethodHead},
		{"TRACE", reflect.TypeOf(traceReq{}), http.MethodTrace},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := DetectHTTPMethod(tt.reqType)
			if method != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, method)
			}
		})
	}
}

func TestDetectHTTPMethod_NoEmbedded(t *testing.T) {
	type invalidReq struct {
		Name string
	}

	defer func() {
		if recover() == nil {
			t.Error("expected panic for request without embedded method type")
		}
	}()

	DetectHTTPMethod(reflect.TypeOf(invalidReq{}))
}

// --- SubRouter Tests ---

func TestNewSubRouter(t *testing.T) {
	engine := gin.New()
	sr := NewSubRouter(&engine.RouterGroup)

	if sr == nil {
		t.Fatal("expected non-nil SubRouter")
	}
	if sr.Gin() != &engine.RouterGroup {
		t.Error("expected Gin() to return the router group")
	}
}

func TestSubRouter_Router(t *testing.T) {
	engine := gin.New()
	sr := NewSubRouter(&engine.RouterGroup)

	sub := sr.Router("/api")
	if sub == nil {
		t.Fatal("expected non-nil sub-router")
	}
	if sub.url != "/api" {
		t.Errorf("expected url=/api, got %s", sub.url)
	}
}

func TestSubRouter_CombineURL(t *testing.T) {
	engine := gin.New()
	sr := NewSubRouter(&engine.RouterGroup)
	sub := sr.Router("/api/v1")

	combined := sub.combineURL("/users")
	if combined != "/api/v1/users" {
		t.Errorf("expected /api/v1/users, got %s", combined)
	}
}

// --- WrapHandler Tests ---

type testRequest struct {
	request.GetRequest
}

type testResponse struct {
	Message string `json:"message"`
}

func TestWrapHandler_Success(t *testing.T) {
	resetGlobals()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler := reflect.ValueOf(func(req *testRequest) testResponse {
		return testResponse{Message: "hello"}
	})

	WrapHandler(c, reflect.TypeOf(testRequest{}), handler, false, nil)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != `{"message":"hello"}` {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
}

func TestWrapHandler_NilResponse(t *testing.T) {
	resetGlobals()

	engine := gin.New()
	engine.GET("/test", func(c *gin.Context) {
		handler := reflect.ValueOf(func(req *testRequest) any {
			return nil
		})
		WrapHandler(c, reflect.TypeOf(testRequest{}), handler, false, nil)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestWrapHandler_WithContext(t *testing.T) {
	resetGlobals()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	SerializeFunc = func(obj interface{}, context ctx.Context) interface{} {
		if prefix, ok := context.GetString("prefix"); ok {
			resp := obj.(testResponse)
			resp.Message = prefix + resp.Message
			return resp
		}
		return obj
	}

	handler := reflect.ValueOf(func(req *testRequest) (testResponse, ctx.Context) {
		return testResponse{Message: "world"}, ctx.Context{"prefix": "hello "}
	})

	WrapHandler(c, reflect.TypeOf(testRequest{}), handler, false, nil)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestWrapHandler_AuthRequired_NoAuth(t *testing.T) {
	resetGlobals()
	HasAuthenticatorFunc = func() bool { return true }
	AuthenticateFunc = func(c *gin.Context) (model.User, error) { return nil, nil }

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler := reflect.ValueOf(func(req *testRequest) testResponse {
		return testResponse{Message: "hello"}
	})

	WrapHandler(c, reflect.TypeOf(testRequest{}), handler, true, nil)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestWrapHandler_AuthRequired_WithAuth(t *testing.T) {
	resetGlobals()
	testUser := &mockUser{id: uuid.New(), roles: []string{"user"}}
	HasAuthenticatorFunc = func() bool { return true }
	AuthenticateFunc = func(c *gin.Context) (model.User, error) { return testUser, nil }

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler := reflect.ValueOf(func(req *testRequest) testResponse {
		return testResponse{Message: "authenticated"}
	})

	WrapHandler(c, reflect.TypeOf(testRequest{}), handler, true, nil)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestWrapHandler_RoleRequired_HasRole(t *testing.T) {
	resetGlobals()
	testUser := &mockUser{id: uuid.New(), roles: []string{"admin"}}
	HasAuthenticatorFunc = func() bool { return true }
	AuthenticateFunc = func(c *gin.Context) (model.User, error) { return testUser, nil }

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler := reflect.ValueOf(func(req *testRequest) testResponse {
		return testResponse{Message: "admin access"}
	})

	WrapHandler(c, reflect.TypeOf(testRequest{}), handler, true, []string{"admin"})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestWrapHandler_RoleRequired_MissingRole(t *testing.T) {
	resetGlobals()
	testUser := &mockUser{id: uuid.New(), roles: []string{"user"}}
	HasAuthenticatorFunc = func() bool { return true }
	AuthenticateFunc = func(c *gin.Context) (model.User, error) { return testUser, nil }

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler := reflect.ValueOf(func(req *testRequest) testResponse {
		return testResponse{Message: "admin access"}
	})

	WrapHandler(c, reflect.TypeOf(testRequest{}), handler, true, []string{"admin"})

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// --- RegisterManually Tests ---

func TestSubRouter_RegisterManually_DryRun(t *testing.T) {
	resetGlobals()

	var collectedRoutes []Route
	IsDryRunFunc = func() bool { return true }
	AddRouteFunc = func(r Route) { collectedRoutes = append(collectedRoutes, r) }
	HasAuthenticatorFunc = func() bool { return false }

	engine := gin.New()
	sr := NewSubRouter(&engine.RouterGroup)
	sub := sr.Router("/api")

	sub.RegisterManually("/users", func(req *testRequest) testResponse {
		return testResponse{}
	}, false)

	if len(collectedRoutes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(collectedRoutes))
	}

	if collectedRoutes[0].Path != "/api/users" {
		t.Errorf("expected path /api/users, got %s", collectedRoutes[0].Path)
	}
	if collectedRoutes[0].Method != http.MethodGet {
		t.Errorf("expected GET method, got %s", collectedRoutes[0].Method)
	}
}

func TestSubRouter_Register(t *testing.T) {
	resetGlobals()
	HasAuthenticatorFunc = func() bool { return true }

	engine := gin.New()
	sr := NewSubRouter(&engine.RouterGroup)

	// Should not panic
	sr.Register("/test", func(req *testRequest) testResponse {
		return testResponse{}
	})
}

func TestSubRouter_RegisterPublic(t *testing.T) {
	resetGlobals()

	engine := gin.New()
	sr := NewSubRouter(&engine.RouterGroup)

	// Should not panic
	sr.RegisterPublic("/test", func(req *testRequest) testResponse {
		return testResponse{}
	})
}

func TestSubRouter_RegisterProtected(t *testing.T) {
	resetGlobals()

	engine := gin.New()
	sr := NewSubRouter(&engine.RouterGroup)

	// Should not panic
	sr.RegisterProtected("/test", func(req *testRequest) testResponse {
		return testResponse{}
	})
}

func TestSubRouter_InvalidHandler(t *testing.T) {
	resetGlobals()

	engine := gin.New()
	sr := NewSubRouter(&engine.RouterGroup)

	defer func() {
		if recover() == nil {
			t.Error("expected panic for invalid handler")
		}
	}()

	// Handler with no parameters
	sr.Register("/test", func() testResponse {
		return testResponse{}
	})
}

func TestSubRouter_NonPointerParam(t *testing.T) {
	resetGlobals()

	engine := gin.New()
	sr := NewSubRouter(&engine.RouterGroup)

	defer func() {
		if recover() == nil {
			t.Error("expected panic for non-pointer parameter")
		}
	}()

	// Handler with non-pointer parameter
	sr.Register("/test", func(req testRequest) testResponse {
		return testResponse{}
	})
}
