package serialize

import (
	"reflect"

	"github.com/sevenitynet/octanox/ctx"
)

// Registry is a map of types to their serializer functions.
type Registry map[reflect.Type]func(interface{}, ctx.Context) any

// Serializer is a type that represents a serializer function.
type Serializer func(interface{}, ctx.Context) any

// NewRegistry creates a new empty serializer registry.
func NewRegistry() Registry {
	return make(Registry)
}

// Serialize serializes an object into another form using the registered serializers.
func (r Registry) Serialize(obj interface{}, c ctx.Context) any {
	serializer, ok := r[reflect.TypeOf(obj)]
	if !ok {
		return obj
	}
	return serializer(obj, c)
}

// Register registers a serializer for a given type.
func (r Registry) Register(obj interface{}, serializer interface{}) Registry {
	typeOfObj := reflect.TypeOf(obj)
	if _, ok := r[typeOfObj]; ok {
		panic("octanox: serializer for type " + typeOfObj.String() + " already registered")
	}

	ftype := reflect.ValueOf(serializer)
	r[typeOfObj] = func(obj interface{}, c ctx.Context) any {
		return ftype.Call([]reflect.Value{reflect.ValueOf(obj), reflect.ValueOf(c)})[0].Interface()
	}

	return r
}
