package middleware

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestBodyDeadline keeps a client from parking a connection on an unfinished body: each read arms an idle deadline that is cleared again as soon as data arrives or EOF is reached, and a body the handler never finished reading gets only drainGrace before net/http's synchronous drain gives up.
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
		// HTTP/2 stream deadlines cannot be re-armed once expired and HTTP/2 never performs the synchronous drain, so only reads are bounded there.
		guard := &bodyDeadline{rc: rc, idle: idle, drainGrace: drainGrace, http1: c.Request.ProtoMajor < 2}
		if guard.http1 {
			if err := rc.SetReadDeadline(time.Now().Add(idle)); err != nil {
				c.Next()
				return
			}
		}
		c.Request.Body = &deadlineBody{ReadCloser: c.Request.Body, guard: guard}
		c.Writer = &deadlineWriter{ResponseWriter: c.Writer, guard: guard}
		c.Next()
		guard.boundDrain()
	}
}

type bodyDeadline struct {
	mu         sync.Mutex
	rc         *http.ResponseController
	idle       time.Duration
	drainGrace time.Duration
	http1      bool
	consumed   bool
	hijacked   bool
	fullDuplex bool
	drainArmed bool
}

// net/http drains an unread HTTP/1 body before the first header write and again after the handler, so both moments get the same short budget.
func (g *bodyDeadline) boundDrain() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.http1 || g.consumed || g.hijacked || g.drainArmed {
		return
	}
	g.drainArmed = true
	_ = g.rc.SetReadDeadline(time.Now().Add(g.drainGrace))
}

// A full-duplex handler reads its body while responding, so the first write must not shorten the body's deadline.
func (g *bodyDeadline) boundDrainOnWrite() {
	g.mu.Lock()
	skip := g.fullDuplex
	g.mu.Unlock()
	if !skip {
		g.boundDrain()
	}
}

func (g *bodyDeadline) armIdle() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.consumed || g.hijacked {
		return
	}
	// A pending drain grace is superseded once the handler reads again, so the post-handler fallback must be free to re-arm it.
	g.drainArmed = false
	_ = g.rc.SetReadDeadline(time.Now().Add(g.idle))
}

func (g *bodyDeadline) clearAfterRead(eof bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.hijacked || g.consumed {
		return
	}
	if eof {
		g.consumed = true
	}
	_ = g.rc.SetReadDeadline(time.Time{})
}

type deadlineBody struct {
	io.ReadCloser
	guard *bodyDeadline
}

// The deadline is live only while blocked waiting for the client, so server-side work between reads never counts as idle time; EOF must clear rather than renew because net/http starts its disconnect read there.
func (b *deadlineBody) Read(p []byte) (int, error) {
	b.guard.armIdle()
	n, err := b.ReadCloser.Read(p)
	switch {
	case errors.Is(err, io.EOF):
		b.guard.clearAfterRead(true)
	case n > 0 && err == nil:
		b.guard.clearAfterRead(false)
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
	w.guard.boundDrainOnWrite()
	return w.ResponseWriter.Write(p)
}

func (w *deadlineWriter) WriteString(s string) (int, error) {
	w.guard.boundDrainOnWrite()
	return w.ResponseWriter.WriteString(s)
}

func (w *deadlineWriter) WriteHeaderNow() {
	w.guard.boundDrainOnWrite()
	w.ResponseWriter.WriteHeaderNow()
}

func (w *deadlineWriter) Flush() {
	w.guard.boundDrainOnWrite()
	w.ResponseWriter.Flush()
}

func (w *deadlineWriter) EnableFullDuplex() error {
	err := http.NewResponseController(w.ResponseWriter).EnableFullDuplex()
	if err == nil {
		w.guard.mu.Lock()
		w.guard.fullDuplex = true
		w.guard.mu.Unlock()
	}
	return err
}

// net/http clears the deadlines when it hands the connection over; the flag keeps the post-handler drain grace from re-arming one on the tunnel.
func (w *deadlineWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := w.ResponseWriter.Hijack()
	if err == nil {
		w.guard.mu.Lock()
		w.guard.hijacked = true
		w.guard.mu.Unlock()
	}
	return conn, rw, err
}
