package request

import (
	"github.com/sevenitynet/octanox/errors"
)

// Request is the base struct for all request types.
type Request struct{}

// Failed is a function that can be called to indicate that the request has failed and should abort with a specific status code and message.
// This function will panic with a FailedRequest struct that will be caught by the Octanox framework.
func (r Request) Failed(status int, message string) {
	panic(errors.FailedRequest{Status: status, Message: message})
}

// GetRequest is a struct that represents a GET request.
type GetRequest struct {
	Request
}

// PostRequest is a struct that represents a POST request.
type PostRequest struct {
	Request
}

// PutRequest is a struct that represents a PUT request.
type PutRequest struct {
	Request
}

// DeleteRequest is a struct that represents a DELETE request.
type DeleteRequest struct {
	Request
}

// PatchRequest is a struct that represents a PATCH request.
type PatchRequest struct {
	Request
}

// OptionsRequest is a struct that represents an OPTIONS request.
type OptionsRequest struct {
	Request
}

// HeadRequest is a struct that represents a HEAD request.
type HeadRequest struct {
	Request
}

// TraceRequest is a struct that represents a TRACE request.
type TraceRequest struct {
	Request
}
