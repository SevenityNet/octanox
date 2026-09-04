package middleware

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestBodyDeadline keeps a client from parking a connection on an unfinished body: the read deadline renews on progress, clears at EOF so long-running handlers keep their context, and drops to drainGrace after a handler that never finished reading so net/http's post-handler drain cannot block forever.
func RequestBodyDeadline(idle, drainGrace time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength == 0 || c.Request.Body == nil || c.Request.Body == http.NoBody {
			c.Next()
			return
		}
		rc := http.NewResponseController(c.Writer)
		if err := rc.SetReadDeadline(time.Now().Add(idle)); err != nil {
			c.Next()
			return
		}
		body := &deadlineBody{ReadCloser: c.Request.Body, rc: rc, idle: idle}
		c.Request.Body = body
		c.Next()
		if !body.consumed {
			_ = rc.SetReadDeadline(time.Now().Add(drainGrace))
		}
	}
}

type deadlineBody struct {
	io.ReadCloser
	rc       *http.ResponseController
	idle     time.Duration
	consumed bool
}

// EOF must clear rather than renew: net/http starts its disconnect read at EOF and a renewed deadline there would cancel a slow handler's context later.
func (b *deadlineBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	switch {
	case errors.Is(err, io.EOF):
		b.consumed = true
		_ = b.rc.SetReadDeadline(time.Time{})
	case n > 0 && err == nil:
		_ = b.rc.SetReadDeadline(time.Now().Add(b.idle))
	}
	return n, err
}
