package request

import (
	"io"
	"net/http"
	"reflect"

	"github.com/goccy/go-json"

	"github.com/gin-gonic/gin"
	"github.com/sevenitynet/octanox/errors"
	"github.com/sevenitynet/octanox/model"
)

// IsDebugFunc is a function variable that returns whether debug mode is enabled.
// This is set by the Instance during initialization.
var IsDebugFunc func() bool

// PopulateRequest extracts the request data from the Gin context, creates a new empty request struct from the given type, and populates it with the extracted data.
func PopulateRequest(c *gin.Context, reqType reflect.Type, user model.User) any {
	reqValue := reflect.New(reqType).Elem()

	for i := 0; i < reqType.NumField(); i++ {
		field := reqType.Field(i)
		fieldValue := reqValue.Field(i)

		if !fieldValue.CanSet() {
			continue
		}

		if field.Anonymous {
			embeddedReq := PopulateRequest(c, field.Type, user)
			fieldValue.Set(reflect.ValueOf(embeddedReq).Elem())
			continue
		}

		if userTag := field.Tag.Get("user"); userTag != "" {
			if user == nil || reflect.DeepEqual(user, reflect.Zero(reflect.TypeOf(user)).Interface()) {
				if userTag != "optional" {
					panic(errors.FailedRequest{
						Status:  http.StatusUnauthorized,
						Message: "Unauthorized: User is required but not provided",
					})
				}

				continue
			}

			if fieldValue.Kind() == reflect.Ptr {
				fieldValue.Set(reflect.ValueOf(user).Addr())
			} else {
				fieldValue.Set(reflect.ValueOf(user))
			}

			continue
		}

		if ginTag := field.Tag.Get("gin"); ginTag != "" {
			if fieldValue.Kind() == reflect.Ptr {
				fieldValue.Set(reflect.ValueOf(c))
			} else {
				panic("field with 'gin' tag must be a pointer to a gin.Context")
			}

			continue
		}

		if pathParam := field.Tag.Get("path"); pathParam != "" {
			fieldValue.SetString(c.Param(pathParam))
		} else if queryParam := field.Tag.Get("query"); queryParam != "" {
			queryValue := c.Query(queryParam)
			if queryValue == "" && field.Tag.Get("optional") != "true" {
				panic(errors.FailedRequest{
					Status:  http.StatusBadRequest,
					Message: "Missing required query parameter: " + queryParam,
				})
			}
			fieldValue.SetString(queryValue)
		} else if headerParam := field.Tag.Get("header"); headerParam != "" {
			headerValue := c.GetHeader(headerParam)
			if headerValue == "" && field.Tag.Get("optional") != "true" {
				panic(errors.FailedRequest{
					Status:  http.StatusBadRequest,
					Message: "Missing required header: " + headerParam,
				})
			}
			fieldValue.SetString(headerValue)
		} else if bodyParam := field.Tag.Get("body"); bodyParam != "" {
			isDebug := IsDebugFunc != nil && IsDebugFunc()

			if field.Type.Kind() == reflect.Ptr {
				bodyInstance := reflect.New(field.Type.Elem()).Interface()

				if err := bindJsonFast(c, bodyInstance); err != nil {
					message := "Invalid JSON body"

					if isDebug {
						message += ": " + err.Error()
					}

					panic(errors.FailedRequest{
						Status:  http.StatusBadRequest,
						Message: message,
					})
				}

				fieldValue.Set(reflect.ValueOf(bodyInstance))
			} else {
				bodyInstance := reflect.New(field.Type).Interface()

				if err := bindJsonFast(c, bodyInstance); err != nil {
					message := "Invalid JSON body"

					if isDebug {
						message += ": " + err.Error()
					}

					panic(errors.FailedRequest{
						Status:  http.StatusBadRequest,
						Message: message,
					})
				}

				fieldValue.Set(reflect.ValueOf(bodyInstance).Elem())
			}
		}
	}

	return reqValue.Addr().Interface()
}

func bindJsonFast(c *gin.Context, v any) error {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(body, v)
}
