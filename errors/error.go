package errors

import (
	"fmt"
	"runtime/debug"
)

// Error wraps the given error and adds a stack trace to it.
func Error(err error) error {
	return fmt.Errorf("%w\n%s", err, string(debug.Stack()))
}
