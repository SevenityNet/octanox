package serialize

import (
	"testing"

	"github.com/sevenitynet/octanox/ctx"
)

type testEntity struct {
	ID   int
	Name string
}

type testDTO struct {
	ID       int    `json:"id"`
	FullName string `json:"full_name"`
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Error("expected non-nil registry")
	}
	if len(r) != 0 {
		t.Errorf("expected empty registry, got %d items", len(r))
	}
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()

	result := r.Register(testEntity{}, func(e testEntity, c ctx.Context) testDTO {
		return testDTO{ID: e.ID, FullName: e.Name}
	})

	// Verify chaining works by checking the result has the serializer
	if len(result) != 1 {
		t.Error("Register should return the same registry for chaining")
	}

	if len(r) != 1 {
		t.Errorf("expected 1 serializer, got %d", len(r))
	}
}

func TestRegistry_Register_Duplicate(t *testing.T) {
	r := NewRegistry()

	r.Register(testEntity{}, func(e testEntity, c ctx.Context) testDTO {
		return testDTO{}
	})

	defer func() {
		if recover() == nil {
			t.Error("expected panic for duplicate registration")
		}
	}()

	r.Register(testEntity{}, func(e testEntity, c ctx.Context) testDTO {
		return testDTO{}
	})
}

func TestRegistry_Serialize(t *testing.T) {
	r := NewRegistry()

	r.Register(testEntity{}, func(e testEntity, c ctx.Context) testDTO {
		prefix := ""
		if name, ok := c.GetString("prefix"); ok {
			prefix = name + " "
		}
		return testDTO{ID: e.ID, FullName: prefix + e.Name}
	})

	entity := testEntity{ID: 1, Name: "John"}
	context := ctx.Context{"prefix": "Mr."}

	result := r.Serialize(entity, context)

	dto, ok := result.(testDTO)
	if !ok {
		t.Fatalf("expected testDTO, got %T", result)
	}

	if dto.ID != 1 {
		t.Errorf("expected ID=1, got %d", dto.ID)
	}
	if dto.FullName != "Mr. John" {
		t.Errorf("expected FullName='Mr. John', got %s", dto.FullName)
	}
}

func TestRegistry_Serialize_NoSerializer(t *testing.T) {
	r := NewRegistry()

	entity := testEntity{ID: 1, Name: "John"}
	result := r.Serialize(entity, nil)

	// Should return original object when no serializer registered
	returned, ok := result.(testEntity)
	if !ok {
		t.Fatalf("expected testEntity, got %T", result)
	}
	if returned != entity {
		t.Error("expected original entity to be returned")
	}
}

func TestRegistry_Serialize_NilContext(t *testing.T) {
	r := NewRegistry()

	r.Register(testEntity{}, func(e testEntity, c ctx.Context) testDTO {
		return testDTO{ID: e.ID, FullName: e.Name}
	})

	entity := testEntity{ID: 1, Name: "John"}
	result := r.Serialize(entity, nil)

	dto, ok := result.(testDTO)
	if !ok {
		t.Fatalf("expected testDTO, got %T", result)
	}

	if dto.FullName != "John" {
		t.Errorf("expected FullName='John', got %s", dto.FullName)
	}
}

func TestRegistry_Chaining(t *testing.T) {
	type Entity2 struct{ Value int }
	type DTO2 struct{ Value int }

	r := NewRegistry().
		Register(testEntity{}, func(e testEntity, c ctx.Context) testDTO {
			return testDTO{ID: e.ID}
		}).
		Register(Entity2{}, func(e Entity2, c ctx.Context) DTO2 {
			return DTO2{Value: e.Value}
		})

	if len(r) != 2 {
		t.Errorf("expected 2 serializers, got %d", len(r))
	}
}

func TestSerializer_Type(t *testing.T) {
	// Verify Serializer is the correct function type
	var s Serializer = func(obj interface{}, c ctx.Context) any {
		return obj
	}

	result := s("test", nil)
	if result != "test" {
		t.Errorf("expected 'test', got %v", result)
	}
}
