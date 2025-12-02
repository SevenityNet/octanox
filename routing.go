package octanox

import (
	"fmt"
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
)

// Router is a struct that represents a router in the Octanox framework. It wraps around a Gin router group with the only two differences
// to populate the request handlers, handling responses and emit the DTOs to the client code generation process.
type SubRouter struct {
	url string
	gin *gin.RouterGroup
}

func (s *SubRouter) combineURL(path string) string {
	return s.url + path
}

// route is a struct containing metadata about a route in the Octanox framework.
type route struct {
	method       string
	path         string
	requestType  reflect.Type
	responseType reflect.Type
}

// Router creates a new router with the given URL prefix.
func (r *SubRouter) Router(url string) *SubRouter {
	return &SubRouter{
		url: url,
		gin: r.gin.Group(url),
	}
}

// Gin returns the underlying Gin router group for adding middleware
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

	method := detectHTTPMethod(reqType)

	if Current.isDryRun {
		Current.routes = append(Current.routes, route{
			method:       method,
			path:         r.combineURL(path),
			requestType:  reqType,
			responseType: resType,
		})
	}

	r.gin.Handle(method, path, func(c *gin.Context) {
		wrapHandler(c, reqType, reflect.ValueOf(handler), authenticated, roles)
	})
}

// Register registers a new route handler. The function automatically detects the method, request and response type. If any of these detection fails, it will panic.
// If an authenticator is set, the route will be protected.
// Should return the response. Can return a Context to set the serializer context.
func (r *SubRouter) Register(path string, handler interface{}, roles ...string) {
	r.RegisterManually(path, handler, Current.Authenticator != nil, roles...)
}

// RegisterPublic registers a new public route handler. The function automatically detects the method, request and response type. If any of these detection fails, it will panic.
func (r *SubRouter) RegisterPublic(path string, handler interface{}, roles ...string) {
	r.RegisterManually(path, handler, false, roles...)
}

// RegisterProtected registers a new protected route handler. The function automatically detects the method, request and response type. If any of these detection fails, it will panic.
func (r *SubRouter) RegisterProtected(path string, handler interface{}, roles ...string) {
	r.RegisterManually(path, handler, true, roles...)
}

// detectHTTPMethod determines the HTTP method from the embedded struct in the request type.
func detectHTTPMethod(reqType reflect.Type) string {
	for i := 0; i < reqType.NumField(); i++ {
		field := reqType.Field(i)

		if field.Anonymous {
			switch field.Type {
			case reflect.TypeOf(GetRequest{}):
				return http.MethodGet
			case reflect.TypeOf(PostRequest{}):
				return http.MethodPost
			case reflect.TypeOf(PutRequest{}):
				return http.MethodPut
			case reflect.TypeOf(DeleteRequest{}):
				return http.MethodDelete
			case reflect.TypeOf(PatchRequest{}):
				return http.MethodPatch
			case reflect.TypeOf(OptionsRequest{}):
				return http.MethodOptions
			case reflect.TypeOf(HeadRequest{}):
				return http.MethodHead
			case reflect.TypeOf(TraceRequest{}):
				return http.MethodTrace
			}
		}
	}

	panic("Failed to detect HTTP method: No recognized embedded request struct found")
}

// wrapHandler wraps the gin context and the handler function to call the handler function with the correct parameters and handle the response.
func wrapHandler(c *gin.Context, reqType reflect.Type, handler reflect.Value, authenticated bool, roles []string) {
	var user User
	if Current.Authenticator != nil {
		usr, err := Current.Authenticator.Authenticate(c)
		if err != nil {
			panic(err)
		}

		if authenticated {
			if usr == nil {
				c.JSON(401, gin.H{"error": "unauthorized"})
				return
			}
		}

		user = usr

		if authenticated {
			if len(roles) > 0 {
				hasRequiredRole := false
				for _, role := range roles {
					if user.HasRole(role) {
						hasRequiredRole = true
						break
					}
				}

				if !hasRequiredRole {
					c.JSON(403, gin.H{"error": "forbidden"})
					return
				}
			}
		}
	}

	req := populateRequest(c, reqType, user)
	rv := handler.Call([]reflect.Value{reflect.ValueOf(req)})
	res := rv[0].Interface()

	var sc Context
	if len(rv) > 1 {
		sc = rv[1].Interface().(Context)
	}

	if res == nil {
		c.Status(204)
		return
	}

	if _, ok := res.(error); ok {
		panic(res)
	}

	c.JSON(200, Current.Serialize(res, sc))
}
