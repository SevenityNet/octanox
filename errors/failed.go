package errors

// FailedRequest represents a failed request with status code and message.
// This struct is used internally by the request and middleware packages.
type FailedRequest struct {
	Status  int
	Message string
}
