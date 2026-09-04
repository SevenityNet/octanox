package middleware

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestBodyDeadline keeps a client from parking a connection on an unfinished body: each read arms an idle deadline that clears at EOF so long-running handlers keep their context, and a body the handler never finished reading gets only drainGrace before net/http's synchronous drain gives up.
func RequestBodyDeadline(idle, drainGrace time.Duration) gin.HandlerFunc {
	return RequestBodyDeadlineFunc(func() (time.Duration, time.Duration) { return idle, drainGrace })
}

// RequestBodyDeadlineFunc resolves the budgets per request so values configured after registration still apply.
func RequestBodyDeadlineFunc(resolve func() (idle, drainGrace time.Duration)) gin.HandlerFunc {
	return func(c *gin.Context) {
		idle, drainGrace := resolve()
		if c.Request.ContentLength == 0 || c.Request.Body == nil || c.Request.Body == http.NoBody {
			c.Next()
			return
		}
		rc := http.NewResponseController(c.Writer)
		// The entry deadline is only a safety net for handlers that never read; every Read re-arms before blocking.
		if err := rc.SetReadDeadline(time.Now().Add(idle)); err != nil {
			c.Next()
			return
		}
		guard := &bodyDeadline{rc: rc, idle: idle, drainGrace: drainGrace}
		c.Request.Body = &deadlineBody{ReadCloser: c.Request.Body, guard: guard}
		c.Writer = &deadlineWriter{ResponseWriter: c.Writer, guard: guard}
		c.Next()
		guard.boundDrain()
	}
}

type bodyDeadline struct {
	rc         *http.ResponseController
	idle       time.Duration
	drainGrace time.Duration
	consumed   bool
	hijacked   bool
	drainArmed bool
}

// net/http drains an unread body before the first header write and again after the handler, so both moments get the same short budget.
func (g *bodyDeadline) boundDrain() {
	if g.consumed || g.hijacked || g.drainArmed {
		return
	}
	g.drainArmed = true
	_ = g.rc.SetReadDeadline(time.Now().Add(g.drainGrace))
}

type deadlineBody struct {
	io.ReadCloser
	guard *bodyDeadline
}

// Arming before the read means server-side work between reads never counts as client idle time; EOF must clear rather than renew because net/http starts its disconnect read there.
func (b *deadlineBody) Read(p []byte) (int, error) {
	g := b.guard
	if !g.consumed && !g.hijacked {
		_ = g.rc.SetReadDeadline(time.Now().Add(g.idle))
	}
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) && !g.consumed {
		g.consumed = true
		_ = g.rc.SetReadDeadline(time.Time{})
	}
	return n, err
}

type deadlineWriter struct {
	gin.ResponseWriter
	guard *bodyDeadline
}

// Unwrap keeps http.NewResponseController working for handlers that manage their own deadlines.
func (w *deadlineWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *deadlineWriter) Write(p []byte) (int, error) {
	w.guard.boundDrain()
	return w.ResponseWriter.Write(p)
}

func (w *deadlineWriter) WriteString(s string) (int, error) {
	w.guard.boundDrain()
	return w.ResponseWriter.WriteString(s)
}

func (w *deadlineWriter) WriteHeaderNow() {
	w.guard.boundDrain()
	w.ResponseWriter.WriteHeaderNow()
}

func (w *deadlineWriter) Flush() {
	w.guard.boundDrain()
	w.ResponseWriter.Flush()
}

// net/http clears the deadlines when it hands the connection over; the flag keeps the post-handler drain grace from re-arming one on the tunnel.
func (w *deadlineWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.guard.hijacked = true
	return w.ResponseWriter.Hijack()
}
