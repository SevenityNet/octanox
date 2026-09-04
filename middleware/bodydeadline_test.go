package middleware

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	testIdle  = 200 * time.Millisecond
	testGrace = 200 * time.Millisecond
)

func newDeadlineServer(t *testing.T, handler gin.HandlerFunc) *httptest.Server {
	return newDeadlineServerWith(t, testIdle, testGrace, handler)
}

func newDeadlineServerWith(t *testing.T, idle, grace time.Duration, handler gin.HandlerFunc) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(RequestBodyDeadline(idle, grace))
	engine.POST("/", handler)
	engine.GET("/", handler)
	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)
	return srv
}

func dialRaw(t *testing.T, srv *httptest.Server) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func writeChunkedPreamble(t *testing.T, conn net.Conn, firstChunk string) {
	t.Helper()
	req := "POST / HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n"
	req += fmt.Sprintf("%x\r\n%s\r\n", len(firstChunk), firstChunk)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write preamble: %v", err)
	}
}

func readStatus(t *testing.T, conn net.Conn, within time.Duration) *http.Response {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(within))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response within %v: %v", within, err)
	}
	return resp
}

func TestRequestBodyDeadlineBoundsDrainWhenHandlerNeverReads(t *testing.T) {
	// A long idle budget isolates the post-handler grace: without it the drain would run the full 5s.
	srv := newDeadlineServerWith(t, 5*time.Second, testGrace, func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
	})
	conn := dialRaw(t, srv)
	writeChunkedPreamble(t, conn, "partial")

	started := time.Now()
	resp := readStatus(t, conn, 3*time.Second)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("rejection took %v, drain was not bounded", elapsed)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatalf("server kept the connection open after an unfinished body")
	}
}

func TestRequestBodyDeadlineClearsAtEOFSoSlowHandlersKeepTheirContext(t *testing.T) {
	srv := newDeadlineServer(t, func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			c.String(http.StatusBadRequest, "read: %v", err)
			return
		}
		time.Sleep(4 * testIdle)
		if err := c.Request.Context().Err(); err != nil {
			c.String(http.StatusInternalServerError, "context: %v", err)
			return
		}
		c.String(http.StatusOK, "alive")
	})
	resp, err := http.Post(srv.URL, "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "alive" {
		t.Fatalf("status = %d body = %q, want 200 alive", resp.StatusCode, body)
	}
}

func TestRequestBodyDeadlineRenewsOnProgress(t *testing.T) {
	srv := newDeadlineServer(t, func(c *gin.Context) {
		data, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusBadRequest, "read: %v", err)
			return
		}
		c.String(http.StatusOK, "%d", len(data))
	})
	conn := dialRaw(t, srv)
	writeChunkedPreamble(t, conn, "aaaa")
	// Six gaps of half the idle budget span three budgets in total, so only renewal keeps the read alive.
	for i := 0; i < 6; i++ {
		time.Sleep(testIdle / 2)
		if _, err := io.WriteString(conn, "4\r\nbbbb\r\n"); err != nil {
			t.Fatalf("write chunk %d: %v", i, err)
		}
	}
	if _, err := io.WriteString(conn, "0\r\n\r\n"); err != nil {
		t.Fatalf("terminate: %v", err)
	}
	resp := readStatus(t, conn, 3*time.Second)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "28" {
		t.Fatalf("status = %d body = %q, want 200 28", resp.StatusCode, body)
	}
}

func TestRequestBodyDeadlineFailsAStalledBodyPromptly(t *testing.T) {
	srv := newDeadlineServer(t, func(c *gin.Context) {
		_, err := io.ReadAll(c.Request.Body)
		if err == nil {
			c.String(http.StatusOK, "unexpected eof")
			return
		}
		c.String(http.StatusRequestTimeout, "timeout")
	})
	conn := dialRaw(t, srv)
	writeChunkedPreamble(t, conn, "first")

	started := time.Now()
	resp := readStatus(t, conn, 3*time.Second)
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want 408", resp.StatusCode)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("stalled read took %v to fail", elapsed)
	}
}

func TestRequestBodyDeadlineLeavesBodylessRequestsAlone(t *testing.T) {
	srv := newDeadlineServer(t, func(c *gin.Context) {
		time.Sleep(2 * testIdle)
		c.String(http.StatusOK, "ok")
	})
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestRequestBodyDeadlineFailsAStallBeforeAnyPayload(t *testing.T) {
	srv := newDeadlineServer(t, func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err == nil {
			c.String(http.StatusOK, "unexpected eof")
			return
		}
		c.String(http.StatusRequestTimeout, "timeout")
	})
	conn := dialRaw(t, srv)
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n"); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	started := time.Now()
	resp := readStatus(t, conn, 3*time.Second)
	if resp.StatusCode != http.StatusRequestTimeout || time.Since(started) > 2*time.Second {
		t.Fatalf("status = %d after %v, want a prompt 408", resp.StatusCode, time.Since(started))
	}
}

func TestRequestBodyDeadlineIgnoresServerWorkBeforeTheFirstRead(t *testing.T) {
	srv := newDeadlineServer(t, func(c *gin.Context) {
		time.Sleep(3 * testIdle)
		data, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusBadRequest, "read: %v", err)
			return
		}
		c.String(http.StatusOK, "%d", len(data))
	})
	conn := dialRaw(t, srv)
	// Expect: 100-continue clients correctly send nothing until the server's first read.
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	interim, err := http.ReadResponse(reader, nil)
	if err != nil || interim.StatusCode != http.StatusContinue {
		t.Fatalf("expected 100 Continue, got %v %v", interim, err)
	}
	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatalf("write body: %v", err)
	}
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "5" {
		t.Fatalf("status = %d body = %q, want 200 5", resp.StatusCode, body)
	}
}

func TestRequestBodyDeadlineBoundsDrainBeforeAnEarlyHeaderFlush(t *testing.T) {
	// Writing past net/http's 2 KiB buffer flushes headers, and therefore drains the unread body, inside the handler.
	srv := newDeadlineServerWith(t, 5*time.Second, testGrace, func(c *gin.Context) {
		c.String(http.StatusTooManyRequests, strings.Repeat("x", 8192))
	})
	conn := dialRaw(t, srv)
	writeChunkedPreamble(t, conn, "partial")
	started := time.Now()
	resp := readStatus(t, conn, 3*time.Second)
	if resp.StatusCode != http.StatusTooManyRequests || time.Since(started) > 2*time.Second {
		t.Fatalf("status = %d after %v, drain before the early flush was not bounded", resp.StatusCode, time.Since(started))
	}
}

func TestRequestBodyDeadlineReleasesAHijackedConnection(t *testing.T) {
	// net/http clears the deadlines at hijack time; the post-handler drain grace must not re-arm one on the tunnel.
	srv := newDeadlineServer(t, func(c *gin.Context) {
		raw, rw, err := c.Writer.Hijack()
		if err != nil {
			c.String(http.StatusInternalServerError, "hijack: %v", err)
			return
		}
		go func() {
			defer raw.Close()
			line, err := rw.ReadString('\n')
			if err != nil {
				_, _ = io.WriteString(raw, "tunnel read failed: "+err.Error()+"\n")
				return
			}
			_, _ = io.WriteString(raw, "echo "+line)
		}()
	})
	conn := dialRaw(t, srv)
	// A one-byte body engages the middleware; the unread byte then legitimately leads the hijacked stream.
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 1\r\n\r\nz"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	time.Sleep(3 * testGrace)
	if _, err := io.WriteString(conn, "late tunnel line\n"); err != nil {
		t.Fatalf("write tunnel line: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.HasSuffix(reply, "late tunnel line\n") {
		t.Fatalf("tunnel reply = %q err = %v, want the echoed line", reply, err)
	}
}

func TestRequestBodyDeadlinePostHandlerGraceCoversASilentHandler(t *testing.T) {
	// The handler never writes, so only the post-handler fallback can bound the drain under a 5s idle budget.
	srv := newDeadlineServerWith(t, 5*time.Second, testGrace, func(c *gin.Context) {})
	conn := dialRaw(t, srv)
	writeChunkedPreamble(t, conn, "partial")
	started := time.Now()
	resp := readStatus(t, conn, 3*time.Second)
	if resp.StatusCode != http.StatusOK || time.Since(started) > 2*time.Second {
		t.Fatalf("status = %d after %v, silent handler drain was not bounded", resp.StatusCode, time.Since(started))
	}
}

func TestRequestBodyDeadlineReArmsGraceAfterAWriteThenPartialRead(t *testing.T) {
	srv := newDeadlineServerWith(t, 5*time.Second, testGrace, func(c *gin.Context) {
		c.Writer.WriteHeader(http.StatusAccepted)
		_, _ = c.Writer.WriteString("started ")
		if _, err := c.Request.Body.Read(make([]byte, 1)); err != nil {
			_, _ = c.Writer.WriteString("read: " + err.Error())
		}
	})
	conn := dialRaw(t, srv)
	writeChunkedPreamble(t, conn, "partial")
	started := time.Now()
	resp := readStatus(t, conn, 3*time.Second)
	if resp.StatusCode != http.StatusAccepted || time.Since(started) > 2*time.Second {
		t.Fatalf("status = %d after %v, stale drain flag left the remainder draining under the idle budget", resp.StatusCode, time.Since(started))
	}
}

func TestRequestBodyDeadlineDoesNotShortenFullDuplexReads(t *testing.T) {
	// Idle stays generous so only a wrongly armed drain grace could fail the read that the concurrent write races.
	srv := newDeadlineServerWith(t, 5*time.Second, testGrace, func(c *gin.Context) {
		if err := http.NewResponseController(c.Writer).EnableFullDuplex(); err != nil {
			c.String(http.StatusInternalServerError, "full duplex: %v", err)
			return
		}
		wrote := make(chan struct{})
		go func() {
			defer close(wrote)
			time.Sleep(testGrace / 2)
			c.Writer.WriteHeader(http.StatusOK)
			_, _ = c.Writer.WriteString("ready\n")
			c.Writer.Flush()
		}()
		data, err := io.ReadAll(c.Request.Body)
		<-wrote
		if err != nil {
			_, _ = c.Writer.WriteString("read: " + err.Error() + "\n")
			return
		}
		_, _ = c.Writer.WriteString(fmt.Sprintf("got %d\n", len(data)))
	})
	conn := dialRaw(t, srv)
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\n"); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	// The body arrives well after the concurrent first write, but inside the idle budget.
	time.Sleep(3 * testGrace)
	if _, err := io.WriteString(conn, "hello"); err != nil {
		t.Fatalf("write body: %v", err)
	}
	resp := readStatus(t, conn, 3*time.Second)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "got 5") {
		t.Fatalf("status = %d body = %q, want a completed full-duplex read", resp.StatusCode, body)
	}
}

func TestRequestBodyDeadlineBoundsDrainOnExplicitClose(t *testing.T) {
	// After a partial read cleared the deadline, Close drains synchronously inside the handler; only the Close hook can bound it.
	for name, close := range map[string]func(c *gin.Context) error{
		"body":           func(c *gin.Context) error { return c.Request.Body.Close() },
		"maxBytesReader": func(c *gin.Context) error { return http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20).Close() },
	} {
		t.Run(name, func(t *testing.T) {
			srv := newDeadlineServerWith(t, 5*time.Second, testGrace, func(c *gin.Context) {
				if _, err := c.Request.Body.Read(make([]byte, 1)); err != nil {
					c.String(http.StatusBadRequest, "read: %v", err)
					return
				}
				_ = close(c)
				c.String(http.StatusAccepted, "closed")
			})
			conn := dialRaw(t, srv)
			writeChunkedPreamble(t, conn, "partial")
			started := time.Now()
			resp := readStatus(t, conn, 3*time.Second)
			if resp.StatusCode != http.StatusAccepted || time.Since(started) > 2*time.Second {
				t.Fatalf("status = %d after %v, Close drained under the idle budget", resp.StatusCode, time.Since(started))
			}
		})
	}
}

type recordingWriter struct {
	gin.ResponseWriter
	deadlines []time.Time
}

func (w *recordingWriter) SetReadDeadline(d time.Time) error {
	w.deadlines = append(w.deadlines, d)
	return nil
}

type scriptedBody struct {
	results []struct {
		n   int
		err error
	}
}

func (b *scriptedBody) Read(p []byte) (int, error) {
	if len(b.results) == 0 {
		return 0, io.EOF
	}
	r := b.results[0]
	b.results = b.results[1:]
	return r.n, r.err
}

func (b *scriptedBody) Close() error { return nil }

func TestRequestBodyDeadlineClearsAfterEveryReadResultAndAtEOF(t *testing.T) {
	// net/http's own EOF clear masks the wrapper's on a real socket, so the deadline sequence is recorded directly.
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	rw := &recordingWriter{ResponseWriter: c.Writer}
	c.Writer = rw
	body := &scriptedBody{}
	body.results = append(body.results,
		struct {
			n   int
			err error
		}{3, nil},
		struct {
			n   int
			err error
		}{2, io.ErrUnexpectedEOF},
		struct {
			n   int
			err error
		}{0, io.EOF},
	)
	c.Request = httptest.NewRequest(http.MethodPost, "/", body)
	c.Request.ContentLength = -1

	RequestBodyDeadline(testIdle, testGrace)(c)
	buf := make([]byte, 8)
	if _, err := c.Request.Body.Read(buf); err != nil {
		t.Fatalf("first read: %v", err)
	}
	if _, err := c.Request.Body.Read(buf); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("second read err = %v", err)
	}
	if _, err := c.Request.Body.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("third read err = %v", err)
	}
	if _, err := c.Request.Body.Read(buf[:0]); err == nil {
		t.Fatalf("zero-length read after EOF should not succeed")
	}

	// entry arm, the post-chain drain grace (no handler ran), then arm/clear per read with EOF's clear last; the zero-length read arms nothing.
	want := []bool{true, true, true, false, true, false, true, false}
	if len(rw.deadlines) != len(want) {
		t.Fatalf("deadline calls = %d (%v), want %d", len(rw.deadlines), rw.deadlines, len(want))
	}
	for i, armed := range want {
		if got := !rw.deadlines[i].IsZero(); got != armed {
			t.Fatalf("deadline call %d armed = %v, want %v (sequence %v)", i, got, armed, rw.deadlines)
		}
	}
}
