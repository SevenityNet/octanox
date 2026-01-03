package middleware

import (
	"os"

	"github.com/gin-gonic/gin"
)

// CORS returns a middleware that handles CORS headers.
// It reads NOX__CORS_ALLOWED_ORIGINS from environment.
func CORS() gin.HandlerFunc {
	corsAllowedOrigin := os.Getenv("NOX__CORS_ALLOWED_ORIGINS")

	return func(c *gin.Context) {
		if corsAllowedOrigin == "*" {
			requestDomain := c.Request.Header.Get("Origin")
			c.Writer.Header().Set("Access-Control-Allow-Origin", requestDomain)
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", corsAllowedOrigin)
		}

		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, PATCH, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Baggage, Accept, Sentry-Trace")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Authorization, Content-Type")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		c.Next()
	}
}
