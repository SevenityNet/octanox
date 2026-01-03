package request

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sevenitynet/octanox/errors"
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

func init() {
	gin.SetMode(gin.TestMode)
}

// --- Request Type Tests ---

func TestRequestTypes(t *testing.T) {
	// Verify all request types embed Request
	types := []interface{}{
		GetRequest{},
		PostRequest{},
		PutRequest{},
		DeleteRequest{},
		PatchRequest{},
		OptionsRequest{},
		HeadRequest{},
		TraceRequest{},
	}

	for _, typ := range types {
		v := reflect.ValueOf(typ)
		if v.NumField() != 1 {
			t.Errorf("%T should have 1 field (embedded Request), got %d", typ, v.NumField())
		}
	}
}

func TestRequest_Failed(t *testing.T) {
	req := Request{}

	defer func() {
		if r := recover(); r != nil {
			fr, ok := r.(errors.FailedRequest)
			if !ok {
				t.Errorf("expected FailedRequest, got %T", r)
			}
			if fr.Status != 400 || fr.Message != "test error" {
				t.Errorf("unexpected FailedRequest: %+v", fr)
			}
		} else {
			t.Error("expected panic")
		}
	}()

	req.Failed(400, "test error")
}

// --- PopulateRequest Tests ---

type testGetRequest struct {
	GetRequest
	ID   string `path:"id"`
	Name string `query:"name" optional:"true"`
}

type testPostRequest struct {
	PostRequest
	Body *testBody `body:"true"`
}

type testBody struct {
	Message string `json:"message"`
}

type testUserRequest struct {
	GetRequest
	User model.User `user:"true"`
}

type testOptionalUserRequest struct {
	GetRequest
	User model.User `user:"optional"`
}

type testHeaderRequest struct {
	GetRequest
	Token string `header:"X-Token"`
}

type testOptionalQueryRequest struct {
	GetRequest
	Filter string `query:"filter" optional:"true"`
}

type testRequiredQueryRequest struct {
	GetRequest
	Filter string `query:"filter"`
}

type testGinContextRequest struct {
	GetRequest
	Ctx *gin.Context `gin:"true"`
}

func TestPopulateRequest_PathParam(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test/123", nil)
	c.Params = gin.Params{{Key: "id", Value: "123"}}

	result := PopulateRequest(c, reflect.TypeOf(testGetRequest{}), nil)
	req := result.(*testGetRequest)

	if req.ID != "123" {
		t.Errorf("expected ID=123, got %s", req.ID)
	}
}

func TestPopulateRequest_QueryParam(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test?name=john", nil)

	result := PopulateRequest(c, reflect.TypeOf(testGetRequest{}), nil)
	req := result.(*testGetRequest)

	if req.Name != "john" {
		t.Errorf("expected Name=john, got %s", req.Name)
	}
}

func TestPopulateRequest_MissingRequiredQuery(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	defer func() {
		if r := recover(); r != nil {
			fr, ok := r.(errors.FailedRequest)
			if !ok {
				t.Errorf("expected FailedRequest, got %T", r)
			}
			if fr.Status != http.StatusBadRequest {
				t.Errorf("expected 400 status, got %d", fr.Status)
			}
		} else {
			t.Error("expected panic for missing required query param")
		}
	}()

	PopulateRequest(c, reflect.TypeOf(testRequiredQueryRequest{}), nil)
}

func TestPopulateRequest_OptionalQuery(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	result := PopulateRequest(c, reflect.TypeOf(testOptionalQueryRequest{}), nil)
	req := result.(*testOptionalQueryRequest)

	if req.Filter != "" {
		t.Errorf("expected empty Filter, got %s", req.Filter)
	}
}

func TestPopulateRequest_Header(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	c.Request.Header.Set("X-Token", "secret-token")

	result := PopulateRequest(c, reflect.TypeOf(testHeaderRequest{}), nil)
	req := result.(*testHeaderRequest)

	if req.Token != "secret-token" {
		t.Errorf("expected Token=secret-token, got %s", req.Token)
	}
}

func TestPopulateRequest_Body(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(`{"message":"hello"}`))
	c.Request.Header.Set("Content-Type", "application/json")

	result := PopulateRequest(c, reflect.TypeOf(testPostRequest{}), nil)
	req := result.(*testPostRequest)

	if req.Body == nil {
		t.Fatal("expected Body to be populated")
	}
	if req.Body.Message != "hello" {
		t.Errorf("expected Message=hello, got %s", req.Body.Message)
	}
}

func TestPopulateRequest_InvalidBody(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(`invalid json`))
	c.Request.Header.Set("Content-Type", "application/json")

	defer func() {
		if r := recover(); r != nil {
			fr, ok := r.(errors.FailedRequest)
			if !ok {
				t.Errorf("expected FailedRequest, got %T", r)
			}
			if fr.Status != http.StatusBadRequest {
				t.Errorf("expected 400 status, got %d", fr.Status)
			}
		} else {
			t.Error("expected panic for invalid JSON")
		}
	}()

	PopulateRequest(c, reflect.TypeOf(testPostRequest{}), nil)
}

func TestPopulateRequest_User(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	testUser := &mockUser{id: uuid.New(), roles: []string{"admin"}}

	result := PopulateRequest(c, reflect.TypeOf(testUserRequest{}), testUser)
	req := result.(*testUserRequest)

	if req.User == nil {
		t.Fatal("expected User to be populated")
	}
	if req.User.ID() != testUser.id {
		t.Errorf("expected User ID %s, got %s", testUser.id, req.User.ID())
	}
}

func TestPopulateRequest_RequiredUserMissing(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	defer func() {
		if r := recover(); r != nil {
			fr, ok := r.(errors.FailedRequest)
			if !ok {
				t.Errorf("expected FailedRequest, got %T", r)
			}
			if fr.Status != http.StatusUnauthorized {
				t.Errorf("expected 401 status, got %d", fr.Status)
			}
		} else {
			t.Error("expected panic for missing required user")
		}
	}()

	PopulateRequest(c, reflect.TypeOf(testUserRequest{}), nil)
}

func TestPopulateRequest_OptionalUserMissing(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	result := PopulateRequest(c, reflect.TypeOf(testOptionalUserRequest{}), nil)
	req := result.(*testOptionalUserRequest)

	if req.User != nil {
		t.Error("expected nil User for optional user")
	}
}

func TestPopulateRequest_GinContext(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	result := PopulateRequest(c, reflect.TypeOf(testGinContextRequest{}), nil)
	req := result.(*testGinContextRequest)

	if req.Ctx != c {
		t.Error("expected Gin context to be populated")
	}
}

func TestPopulateRequest_IsDebugFunc(t *testing.T) {
	// Test that IsDebugFunc is called for body parsing errors
	IsDebugFunc = func() bool { return true }
	defer func() { IsDebugFunc = nil }()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(`invalid`))

	defer func() {
		if r := recover(); r != nil {
			fr := r.(errors.FailedRequest)
			// In debug mode, error should contain more details
			if fr.Message == "Invalid JSON body" {
				t.Error("expected detailed error message in debug mode")
			}
		}
	}()

	PopulateRequest(c, reflect.TypeOf(testPostRequest{}), nil)
}
