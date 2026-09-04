package middleware

import (
	"bufio"
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
