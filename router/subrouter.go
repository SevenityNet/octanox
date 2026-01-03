package router

import (
	"fmt"
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/sevenitynet/octanox/request"
)

// SubRouter is a struct that represents a router in the Octanox framework.
// It wraps around a Gin router group with the only two differences
// to populate the request handlers, handling responses and emit the DTOs to the client code generation process.
type SubRouter struct {
	url string
	gin *gin.RouterGroup
}

// NewSubRouter creates a new SubRouter from a Gin router group.
func NewSubRouter(gin *gin.RouterGroup) *SubRouter {
	return &SubRouter{
		url: "",
		gin: gin,
	}
}

func (s *SubRouter) combineURL(path string) string {
	return s.url + path
}

// Router creates a new router with the given URL prefix.
func (r *SubRouter) Router(url string) *SubRouter {
	return &SubRouter{
		url: url,
		gin: r.gin.Group(url),
	}
}

// Gin returns the underlying Gin router group for adding middleware.
func (r *SubRouter) Gin() *gin.RouterGroup {
	return r.gin
}

// RegisterManually registers a new route handler. The function automatically detects the method, request and response type. If any of these detection fails, it will panic.
func (r *SubRouter) RegisterManually(path string, handler interface{}, authenticated bool, roles ...string) {
	handlerType := reflect.TypeOf(handler)

	if handlerType.Kind() != reflect.Func || handlerType.NumIn() != 1 || handlerType.NumOut() < 1 {
		panic("Handler function must have one input parameter and at least one return value, in: " + fmt.Sprintf("%d", handlerType.NumIn()) + ", out: " + fmt.Sprintf("%d", handlerType.NumOut()))
	}

	reqType := handlerType.In(0)
	if reqType.Kind() == reflect.Ptr {
		reqType = reqType.Elem()
	} else {
		panic("Handler function input parameter must be a pointer")
	}

	resType := handlerType.Out(0)

	method := DetectHTTPMethod(reqType)

	if IsDryRunFunc != nil && IsDryRunFunc() {
		if AddRouteFunc != nil {
			AddRouteFunc(Route{
				Method:       method,
				Path:         r.combineURL(path),
				RequestType:  reqType,
				ResponseType: resType,
			})
		}
	}

	r.gin.Handle(method, path, func(c *gin.Context) {
		WrapHandler(c, reqType, reflect.ValueOf(handler), authenticated, roles)
	})
}

// Register registers a new route handler. The function automatically detects the method, request and response type. If any of these detection fails, it will panic.
// If an authenticator is set, the route will be protected.
// Should return the response. Can return a Context to set the serializer context.
func (r *SubRouter) Register(path string, handler interface{}, roles ...string) {
	hasAuth := HasAuthenticatorFunc != nil && HasAuthenticatorFunc()
	r.RegisterManually(path, handler, hasAuth, roles...)
}

// RegisterPublic registers a new public route handler. The function automatically detects the method, request and response type. If any of these detection fails, it will panic.
func (r *SubRouter) RegisterPublic(path string, handler interface{}, roles ...string) {
	r.RegisterManually(path, handler, false, roles...)
}

// RegisterProtected registers a new protected route handler. The function automatically detects the method, request and response type. If any of these detection fails, it will panic.
func (r *SubRouter) RegisterProtected(path string, handler interface{}, roles ...string) {
	r.RegisterManually(path, handler, true, roles...)
}

// DetectHTTPMethod determines the HTTP method from the embedded struct in the request type.
func DetectHTTPMethod(reqType reflect.Type) string {
	for i := 0; i < reqType.NumField(); i++ {
		field := reqType.Field(i)

		if field.Anonymous {
			switch field.Type {
			case reflect.TypeOf(request.GetRequest{}):
				return http.MethodGet
			case reflect.TypeOf(request.PostRequest{}):
				return http.MethodPost
			case reflect.TypeOf(request.PutRequest{}):
				return http.MethodPut
			case reflect.TypeOf(request.DeleteRequest{}):
				return http.MethodDelete
			case reflect.TypeOf(request.PatchRequest{}):
				return http.MethodPatch
			case reflect.TypeOf(request.OptionsRequest{}):
				return http.MethodOptions
			case reflect.TypeOf(request.HeadRequest{}):
				return http.MethodHead
			case reflect.TypeOf(request.TraceRequest{}):
				return http.MethodTrace
			}
		}
	}

	panic("Failed to detect HTTP method: No recognized embedded request struct found")
}
