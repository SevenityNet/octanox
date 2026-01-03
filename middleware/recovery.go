package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/sevenitynet/octanox/errors"
)

// EmitErrorFunc is a function variable for emitting errors.
// This is set by the root octanox package during initialization.
var EmitErrorFunc func(error)

// Recovery returns a middleware that recovers from panics.
// It handles FailedRequest panics specially, returning the status and message.
// Other panics are logged and return 500.
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				failedReq, ok := err.(errors.FailedRequest)
				if ok {
					c.JSON(failedReq.Status, gin.H{"error": failedReq.Message})
					return
				}

				wrappedErr := errors.Error(fmt.Errorf("internal REST Server Error: %v", err))
				if EmitErrorFunc != nil {
					EmitErrorFunc(wrappedErr)
				}

				c.JSON(500, gin.H{"error": "Internal Server Error"})
			}
		}()
		c.Next()
	}
}
