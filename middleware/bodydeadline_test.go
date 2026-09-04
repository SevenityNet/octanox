package middleware

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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
	// net/http's own EOF clear masks the wrapper's on a real socket, so the deadline sequence is recorded directly through a handler chain.
	gin.SetMode(gin.TestMode)
	var rw *recordingWriter
	var readErrs []error
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		rw = &recordingWriter{ResponseWriter: c.Writer}
		c.Writer = rw
		c.Next()
	})
	engine.Use(RequestBodyDeadline(testIdle, testGrace))
	engine.POST("/", func(c *gin.Context) {
		buf := make([]byte, 8)
		for i := 0; i < 4; i++ {
			_, err := c.Request.Body.Read(buf)
			readErrs = append(readErrs, err)
		}
		_, err := c.Request.Body.Read(buf[:0])
		readErrs = append(readErrs, err)
		c.Status(http.StatusNoContent)
	})
	body := &scriptedBody{}
	body.results = append(body.results,
		struct {
			n   int
			err error
		}{3, nil},
		struct {
			n   int
			err error
		}{0, nil},
		struct {
			n   int
			err error
		}{2, io.ErrUnexpectedEOF},
		struct {
			n   int
			err error
		}{0, io.EOF},
	)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.ContentLength = -1
	engine.ServeHTTP(httptest.NewRecorder(), req)

	if len(readErrs) != 5 || readErrs[0] != nil || readErrs[1] != nil || !errors.Is(readErrs[2], io.ErrUnexpectedEOF) || !errors.Is(readErrs[3], io.EOF) {
		t.Fatalf("read errors = %v", readErrs)
	}
	// entry arm, then arm/clear per read including the no-progress one, with EOF's clear last; the zero-length read arms nothing and the consumed body needs no post-handler grace.
	want := []bool{true, true, false, true, false, true, false, true, false}
	if len(rw.deadlines) != len(want) {
		t.Fatalf("deadline calls = %d (%v), want %d", len(rw.deadlines), rw.deadlines, len(want))
	}
	for i, armed := range want {
		if got := !rw.deadlines[i].IsZero(); got != armed {
			t.Fatalf("deadline call %d armed = %v, want %v (sequence %v)", i, got, armed, rw.deadlines)
		}
	}
}

func TestRequestBodyDeadlineCloseGraceSurvivesARacingRead(t *testing.T) {
	// A Read that completes with progress while Close is pending must not clear the close grace; the client feeds one late chunk then stalls.
	srv := newDeadlineServerWith(t, 5*time.Second, testGrace, func(c *gin.Context) {
		readDone := make(chan error, 1)
		go func() {
			_, err := c.Request.Body.Read(make([]byte, 16))
			readDone <- err
		}()
		time.Sleep(testGrace / 4)
		closeErr := c.Request.Body.Close()
		select {
		case <-readDone:
		case <-time.After(3 * time.Second):
			c.String(http.StatusInternalServerError, "read never returned")
			return
		}
		c.String(http.StatusAccepted, "close=%v", closeErr)
	})
	conn := dialRaw(t, srv)
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n"); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	started := time.Now()
	time.Sleep(testGrace / 2)
	if _, err := io.WriteString(conn, "5\r\nlate!\r\n"); err != nil {
		t.Fatalf("write late chunk: %v", err)
	}
	resp := readStatus(t, conn, 3*time.Second)
	if resp.StatusCode != http.StatusAccepted || time.Since(started) > 2*time.Second {
		t.Fatalf("status = %d after %v, racing read disturbed the close grace", resp.StatusCode, time.Since(started))
	}
}

func TestRequestBodyDeadlineKeepsAliveAfterASuccessfulCloseDrain(t *testing.T) {
	srv := newDeadlineServer(t, func(c *gin.Context) {
		if _, err := c.Request.Body.Read(make([]byte, 1)); err != nil {
			c.String(http.StatusBadRequest, "read: %v", err)
			return
		}
		_ = c.Request.Body.Close()
		c.String(http.StatusOK, "ok")
	})
	conn := dialRaw(t, srv)
	reader := bufio.NewReader(conn)
	for i := 0; i < 2; i++ {
		if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\nhello"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("request %d: read response: %v (connection not reused after a close-drained body)", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK || resp.Close {
			t.Fatalf("request %d: status = %d close = %v, want a reusable 200", i, resp.StatusCode, resp.Close)
		}
	}
}

func TestRequestBodyDeadlineDoesNotReuseAConnectionAfterAnIncompleteClose(t *testing.T) {
	// Reusing the connection here would let the unread body bytes be parsed as the next request.
	srv := newDeadlineServer(t, func(c *gin.Context) {
		if _, err := c.Request.Body.Read(make([]byte, 1)); err != nil {
			c.String(http.StatusBadRequest, "read: %v", err)
			return
		}
		_ = c.Request.Body.Close()
		c.String(http.StatusAccepted, "closed")
	})
	conn := dialRaw(t, srv)
	reader := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 400000\r\n\r\nx"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("first response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("first status = %d, want 202", resp.StatusCode)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: test\r\n\r\n"); err != nil {
		t.Fatalf("write second request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	second, err := http.ReadResponse(reader, nil)
	if err == nil {
		t.Fatalf("server answered a second request (status %d) on a connection with unread body bytes", second.StatusCode)
	}
	requireClosed(t, err)
}

// http.ReadResponse reports a closed connection as unexpected EOF; a timeout would mean the server is still holding it open.
func requireClosed(t *testing.T, err error) {
	t.Helper()
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("second request timed out instead of the server closing the connection: %v", err)
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("second request err = %v, want a closed connection", err)
	}
}

// expectNoReuse sends a valid second request on conn and requires the server to have closed it.
func expectNoReuse(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: test\r\n\r\n"); err != nil {
		t.Fatalf("write second request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	second, err := http.ReadResponse(reader, nil)
	if err == nil {
		t.Fatalf("server answered a second request (status %d) on a connection with unread body bytes", second.StatusCode)
	}
	requireClosed(t, err)
}

func TestRequestBodyDeadlineNoReuseAfterExpectContinueClose(t *testing.T) {
	srv := newDeadlineServer(t, func(c *gin.Context) {
		if _, err := c.Request.Body.Read(make([]byte, 1)); err != nil {
			c.String(http.StatusBadRequest, "read: %v", err)
			return
		}
		_ = c.Request.Body.Close()
		c.Writer.WriteHeader(http.StatusAccepted)
		_, _ = c.Writer.WriteString("closed")
	})
	conn := dialRaw(t, srv)
	reader := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 400000\r\nExpect: 100-continue\r\n\r\n"); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if interim, err := http.ReadResponse(reader, nil); err != nil || interim.StatusCode != http.StatusContinue {
		t.Fatalf("expected 100 Continue, got %v %v", interim, err)
	}
	if _, err := io.WriteString(conn, "x"); err != nil {
		t.Fatalf("write first byte: %v", err)
	}
	resp, err := http.ReadResponse(reader, nil)
	if err != nil || resp.StatusCode != http.StatusAccepted {
		t.Fatalf("response = %v %v, want 202", resp, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	expectNoReuse(t, conn, reader)
}

func fullDuplexLargeBodyHandler(replaceRequest bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if replaceRequest {
			c.Request = c.Request.WithContext(c.Request.Context())
		}
		if err := http.NewResponseController(c.Writer).EnableFullDuplex(); err != nil {
			c.String(http.StatusInternalServerError, "full duplex: %v", err)
			return
		}
		if _, err := c.Request.Body.Read(make([]byte, 1)); err != nil {
			c.String(http.StatusBadRequest, "read: %v", err)
			return
		}
		c.Writer.WriteHeader(http.StatusAccepted)
		_, _ = c.Writer.WriteString("partial")
		c.Writer.Flush()
	}
}

func TestRequestBodyDeadlineNoReuseAfterFullDuplexWithIncompleteBody(t *testing.T) {
	for name, replace := range map[string]bool{"plain": false, "requestReplacedWithContext": true} {
		t.Run(name, func(t *testing.T) {
			srv := newDeadlineServer(t, fullDuplexLargeBodyHandler(replace))
			conn := dialRaw(t, srv)
			reader := bufio.NewReader(conn)
			if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 400000\r\n\r\nx"); err != nil {
				t.Fatalf("write request: %v", err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			resp, err := http.ReadResponse(reader, nil)
			if err != nil || resp.StatusCode != http.StatusAccepted {
				t.Fatalf("response = %v %v, want 202", resp, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			expectNoReuse(t, conn, reader)
		})
	}
}

func TestRequestBodyDeadlineHandsMultipartFormBackForCleanup(t *testing.T) {
	// net/http removes multipart temp files from its own request, so a form parsed on the handler's copy must reach it.
	gin.SetMode(gin.TestMode)
	var serverReq *http.Request
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		serverReq = c.Request
		// The recorder cannot take a read deadline, so the middleware would otherwise skip wrapping entirely.
		c.Writer = &recordingWriter{ResponseWriter: c.Writer}
		c.Next()
	})
	engine.Use(RequestBodyDeadline(testIdle, testGrace))
	engine.POST("/", func(c *gin.Context) {
		if c.Request == serverReq {
			c.String(http.StatusInternalServerError, "handler saw the server request, middleware did not wrap")
			return
		}
		if _, err := c.FormFile("f"); err != nil {
			c.String(http.StatusBadRequest, "form: %v", err)
			return
		}
		c.Status(http.StatusNoContent)
	})
	body := "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"f.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--\r\n"
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if serverReq.MultipartForm == nil || len(serverReq.MultipartForm.File["f"]) != 1 {
		t.Fatalf("server request did not receive the parsed multipart form for cleanup")
	}
}

func TestRequestBodyDeadlineExposesUndeclaredChunkedTrailers(t *testing.T) {
	srv := newDeadlineServer(t, func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			c.String(http.StatusBadRequest, "read: %v", err)
			return
		}
		c.String(http.StatusOK, "trailer=%s", c.Request.Trailer.Get("X-Checksum"))
	})
	conn := dialRaw(t, srv)
	if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := readStatus(t, conn, 3*time.Second)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "trailer=abc" {
		t.Fatalf("status = %d body = %q, want the undeclared trailer", resp.StatusCode, body)
	}
}

func TestRequestBodyDeadlineMultipartTempFileIsRemovedAfterTheResponse(t *testing.T) {
	var tmpPath string
	srv := newDeadlineServer(t, func(c *gin.Context) {
		// A one-byte memory budget forces the part onto disk, which is the case net/http must clean up.
		if err := c.Request.ParseMultipartForm(1); err != nil {
			c.String(http.StatusBadRequest, "parse: %v", err)
			return
		}
		fh := c.Request.MultipartForm.File["f"][0]
		f, err := fh.Open()
		if err != nil {
			c.String(http.StatusInternalServerError, "open: %v", err)
			return
		}
		defer f.Close()
		if osf, ok := f.(*os.File); ok {
			tmpPath = osf.Name()
		}
		c.Status(http.StatusNoContent)
	})
	body := "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"f.txt\"\r\nContent-Type: text/plain\r\n\r\nhello there\r\n--b--\r\n"
	resp, err := http.Post(srv.URL, "multipart/form-data; boundary=b", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if tmpPath == "" {
		t.Fatalf("the part did not spill to disk, test is not exercising cleanup")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(tmpPath); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("multipart temp file %s still exists after the response", tmpPath)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRequestBodyDeadlineHandsBackFormParsedBeforeRequestReplacement(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var serverReq *http.Request
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		serverReq = c.Request
		c.Writer = &recordingWriter{ResponseWriter: c.Writer}
		c.Next()
	})
	engine.Use(RequestBodyDeadline(testIdle, testGrace))
	engine.POST("/", func(c *gin.Context) {
		if _, err := c.FormFile("f"); err != nil {
			c.String(http.StatusBadRequest, "form: %v", err)
			return
		}
		// An unrelated replacement must neither lose the parsed form nor hand its own form to net/http.
		c.Request = httptest.NewRequest(http.MethodGet, "/other", nil)
		c.Status(http.StatusNoContent)
	})
	body := "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"f.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--\r\n"
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if serverReq.MultipartForm == nil || len(serverReq.MultipartForm.File["f"]) != 1 {
		t.Fatalf("form parsed before the request was replaced was not handed back")
	}
}

func TestRequestBodyDeadlineMultipartHandBackFollowsRequestLineage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	body := "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"f.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--\r\n"
	run := func(t *testing.T, handler gin.HandlerFunc) *http.Request {
		var serverReq *http.Request
		engine := gin.New()
		engine.Use(func(c *gin.Context) {
			serverReq = c.Request
			c.Writer = &recordingWriter{ResponseWriter: c.Writer}
			c.Next()
		})
		engine.Use(RequestBodyDeadline(testIdle, testGrace))
		engine.POST("/", handler)
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
		return serverReq
	}
	t.Run("derived request is adopted", func(t *testing.T) {
		serverReq := run(t, func(c *gin.Context) {
			c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), "k", "v"))
			if _, err := c.FormFile("f"); err != nil {
				c.String(http.StatusBadRequest, "form: %v", err)
				return
			}
			c.Status(http.StatusNoContent)
		})
		if serverReq.MultipartForm == nil {
			t.Fatalf("form parsed on a context-derived request was not handed back")
		}
	})
	t.Run("unrelated request is not adopted", func(t *testing.T) {
		serverReq := run(t, func(c *gin.Context) {
			other := httptest.NewRequest(http.MethodPost, "/other", strings.NewReader(body))
			other.Header.Set("Content-Type", "multipart/form-data; boundary=b")
			if err := other.ParseMultipartForm(1 << 20); err != nil {
				c.String(http.StatusBadRequest, "parse: %v", err)
				return
			}
			c.Request = other
			c.Status(http.StatusNoContent)
		})
		if serverReq.MultipartForm != nil {
			t.Fatalf("an unrelated request's form was handed to net/http for removal")
		}
	})
}
