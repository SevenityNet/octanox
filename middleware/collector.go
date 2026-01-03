package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// ErrorCollector returns a middleware that collects errors from the Gin context
// and emits them to the error handlers.
func ErrorCollector() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := fmt.Errorf("gin error: %s", c.Errors.String())
			if EmitErrorFunc != nil {
				EmitErrorFunc(err)
			}
		}
	}
}
