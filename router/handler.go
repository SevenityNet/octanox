package router

import (
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/sevenitynet/octanox/ctx"
	"github.com/sevenitynet/octanox/model"
	"github.com/sevenitynet/octanox/request"
)

// Function variables to break circular dependencies with Instance.
// These are set by the root octanox package during initialization.
var (
	// IsDryRunFunc returns whether the instance is in dry-run mode.
	IsDryRunFunc func() bool
	// AddRouteFunc adds a route to the instance's route collection (for code generation).
	AddRouteFunc func(Route)
	// HasAuthenticatorFunc returns whether an authenticator is configured.
	HasAuthenticatorFunc func() bool
	// AuthenticateFunc authenticates a request and returns the user.
	AuthenticateFunc func(c *gin.Context) (model.User, error)
	// SerializeFunc serializes an object using the instance's serializer registry.
	SerializeFunc func(obj interface{}, c ctx.Context) interface{}
)

// WrapHandler wraps the gin context and the handler function to call the handler function with the correct parameters and handle the response.
func WrapHandler(c *gin.Context, reqType reflect.Type, handler reflect.Value, authenticated bool, roles []string) {
	var user model.User
	if HasAuthenticatorFunc != nil && HasAuthenticatorFunc() && AuthenticateFunc != nil {
		usr, err := AuthenticateFunc(c)
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

	req := request.PopulateRequest(c, reqType, user)
	rv := handler.Call([]reflect.Value{reflect.ValueOf(req)})
	res := rv[0].Interface()

	var sc ctx.Context
	if len(rv) > 1 {
		sc = rv[1].Interface().(ctx.Context)
	}

	if res == nil {
		// Only set 204 if response hasn't already been written (e.g., by SSE streaming)
		if !c.Writer.Written() {
			c.Status(204)
		}
		return
	}

	if _, ok := res.(error); ok {
		panic(res)
	}

	// Serialize the response if a serializer is available
	if SerializeFunc != nil {
		res = SerializeFunc(res, sc)
	}

	c.JSON(200, res)
}
