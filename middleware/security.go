package middleware

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// CSPConfig holds Content Security Policy directives.
type CSPConfig struct {
	DefaultSrc     []string
	ScriptSrc      []string
	StyleSrc       []string
	ImgSrc         []string
	FontSrc        []string
	ConnectSrc     []string
	FrameSrc       []string
	WorkerSrc      []string
	ObjectSrc      []string
	BaseURI        []string
	FormAction     []string
	FrameAncestors []string
	ReportOnly     bool
}

// Build compiles the CSP config into a policy string.
// Only includes directives that have values. Example output:
// "default-src 'none'; frame-ancestors 'none'"
func (c CSPConfig) Build() string {
	type directive struct {
		name   string
		values []string
	}

	directives := []directive{
		{"default-src", c.DefaultSrc},
		{"script-src", c.ScriptSrc},
		{"style-src", c.StyleSrc},
		{"img-src", c.ImgSrc},
		{"font-src", c.FontSrc},
		{"connect-src", c.ConnectSrc},
		{"frame-src", c.FrameSrc},
		{"worker-src", c.WorkerSrc},
		{"object-src", c.ObjectSrc},
		{"base-uri", c.BaseURI},
		{"form-action", c.FormAction},
		{"frame-ancestors", c.FrameAncestors},
	}

	var parts []string
	for _, d := range directives {
		if len(d.values) == 0 {
			continue
		}
		parts = append(parts, d.name+" "+strings.Join(d.values, " "))
	}

	return strings.Join(parts, "; ")
}

// DefaultAPICSP returns a strict CSP suitable for JSON API backends.
func DefaultAPICSP() CSPConfig {
	return CSPConfig{
		DefaultSrc:     []string{"'none'"},
		FrameAncestors: []string{"'none'"},
	}
}

// SwaggerCSP returns middleware that sets a permissive CSP suitable for Swagger UI.
// Use this as route-level middleware on documentation endpoints.
func SwaggerCSP() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'")
		c.Next()
	}
}

// SecurityHeaders returns middleware that sets Content-Security-Policy.
// Without arguments, uses DefaultAPICSP().
// Pass a CSPConfig to customize the policy.
// The env var NOX__CSP_POLICY overrides everything with a raw policy string.
func SecurityHeaders(cfg ...CSPConfig) gin.HandlerFunc {
	config := DefaultAPICSP()
	if len(cfg) > 0 {
		config = cfg[0]
	}

	// Build the policy string once at init time (not per-request).
	policy := config.Build()

	// Allow env var to completely override.
	if envPolicy := os.Getenv("NOX__CSP_POLICY"); envPolicy != "" {
		policy = envPolicy
	}

	reportOnly := config.ReportOnly
	if v := os.Getenv("NOX__CSP_REPORT_ONLY"); v == "true" || v == "1" {
		reportOnly = true
	}

	headerName := "Content-Security-Policy"
	if reportOnly {
		headerName = "Content-Security-Policy-Report-Only"
	}

	return func(c *gin.Context) {
		c.Writer.Header().Set(headerName, policy)
		c.Next()
	}
}
