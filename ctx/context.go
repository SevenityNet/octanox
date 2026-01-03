package ctx

import "github.com/gin-gonic/gin"

// Context is a type that represents a generic context.
type Context map[string]interface{}

// FromMap is a function that converts a map to a Context.
func FromMap(m map[string]interface{}) Context {
	return Context(m)
}

// FromQuery is a function that converts a Gin context (query parameters) to a Context.
func FromQuery(c *gin.Context) Context {
	query := c.Request.URL.Query()
	context := make(Context)
	for key, value := range query {
		if len(value) == 1 {
			context[key] = value[0]
		} else {
			context[key] = value
		}
	}
	return context
}

// Set is a function that sets a key-value pair to a Context.
func (c Context) Set(key string, value interface{}) Context {
	c[key] = value
	return c
}

// Has is a function that checks if a Context has a key.
func (c Context) Has(key string) bool {
	_, ok := c[key]
	return ok
}

// Get is a function that gets a value from a Context.
func (c Context) Get(key string) (interface{}, bool) {
	value, ok := c[key]
	return value, ok
}

// GetString is a function that gets a string value from a Context.
func (c Context) GetString(key string) (string, bool) {
	value, ok := c[key]
	if !ok {
		return "", false
	}

	str, ok := value.(string)
	return str, ok
}

// GetInt is a function that gets an int value from a Context.
func (c Context) GetInt(key string) (int, bool) {
	value, ok := c[key]
	if !ok {
		return 0, false
	}

	num, ok := value.(int)
	return num, ok
}

// GetFloat is a function that gets a float64 value from a Context.
func (c Context) GetFloat(key string) (float64, bool) {
	value, ok := c[key]
	if !ok {
		return 0, false
	}

	num, ok := value.(float64)
	return num, ok
}

// GetBool is a function that gets a bool value from a Context.
func (c Context) GetBool(key string) (bool, bool) {
	value, ok := c[key]
	if !ok {
		return false, false
	}

	b, ok := value.(bool)
	return b, ok
}

// GetStringSlice is a function that gets a string slice value from a Context.
func (c Context) GetStringSlice(key string) ([]string, bool) {
	value, ok := c[key]
	if !ok {
		return nil, false
	}

	slice, ok := value.([]string)
	return slice, ok
}
