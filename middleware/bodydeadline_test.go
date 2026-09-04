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
