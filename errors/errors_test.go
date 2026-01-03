package errors

import (
	"errors"
	"strings"
	"testing"
)

func TestError(t *testing.T) {
	originalErr := errors.New("test error")
	wrappedErr := Error(originalErr)

	if wrappedErr == nil {
		t.Fatal("expected wrapped error, got nil")
	}

	// Should contain original error message
	if !strings.Contains(wrappedErr.Error(), "test error") {
		t.Errorf("expected error to contain 'test error', got %s", wrappedErr.Error())
	}

	// Should contain stack trace
	if !strings.Contains(wrappedErr.Error(), "goroutine") {
		t.Errorf("expected error to contain stack trace")
	}

	// Should be unwrappable to original error
	if !errors.Is(wrappedErr, originalErr) {
		t.Error("expected wrapped error to unwrap to original")
	}
}

func TestFailedRequest(t *testing.T) {
	fr := FailedRequest{
		Status:  404,
		Message: "Not Found",
	}

	if fr.Status != 404 {
		t.Errorf("expected status 404, got %d", fr.Status)
	}
	if fr.Message != "Not Found" {
		t.Errorf("expected message 'Not Found', got %s", fr.Message)
	}
}

func TestFailedRequestAsValue(t *testing.T) {
	// Test that FailedRequest can be used as a panic value
	defer func() {
		if r := recover(); r != nil {
			fr, ok := r.(FailedRequest)
			if !ok {
				t.Error("expected FailedRequest type from recover")
			}
			if fr.Status != 400 || fr.Message != "Bad Request" {
				t.Errorf("unexpected FailedRequest values: %+v", fr)
			}
		}
	}()

	panic(FailedRequest{Status: 400, Message: "Bad Request"})
}
