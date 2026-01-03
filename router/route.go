package router

import "reflect"

// Route is a struct containing metadata about a route in the Octanox framework.
type Route struct {
	Method       string
	Path         string
	RequestType  reflect.Type
	ResponseType reflect.Type
}
