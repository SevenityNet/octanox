package middleware

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORS handles CORS headers; allowed origins come from NOX__CORS_ALLOWED_ORIGINS (comma-separated).
func CORS() gin.HandlerFunc {
	allowHeaders := appendExtraHeaders("Authorization, Content-Type, Baggage, Accept, Sentry-Trace, X-App-Version", "NOX__CORS_EXTRA_ALLOWED_HEADERS")
	exposeHeaders := appendExtraHeaders("Authorization, Content-Type", "NOX__CORS_EXTRA_EXPOSE_HEADERS")

	var allowed []string
	wildcard := false
	for _, o := range strings.Split(os.Getenv("NOX__CORS_ALLOWED_ORIGINS"), ",") {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if o == "*" {
			wildcard = true
			continue
		}
		allowed = append(allowed, o)
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		// Response varies by Origin, so caches must key on it even when no match is found.
		c.Writer.Header().Add("Vary", "Origin")

		allowOrigin := ""
		if wildcard {
			// Credentialed responses cannot use "*", so reflect the request origin instead.
			allowOrigin = origin
		} else {
			for _, o := range allowed {
				if o == origin {
					allowOrigin = origin
					break
				}
			}
		}

		if allowOrigin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, PATCH, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", allowHeaders)
		c.Writer.Header().Set("Access-Control-Expose-Headers", exposeHeaders)

		// Answer preflight here, before any downstream auth middleware could reject it.
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}

		c.Next()
	}
}

func appendExtraHeaders(defaults, envKey string) string {
	if extra := strings.TrimSpace(os.Getenv(envKey)); extra != "" {
		return defaults + ", " + extra
	}
	return defaults
}
