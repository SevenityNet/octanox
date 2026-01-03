package middleware

import "github.com/gin-gonic/gin"

// Logger returns the default Gin logger middleware.
func Logger() gin.HandlerFunc {
	return gin.Logger()
}
