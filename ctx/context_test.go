package ctx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestFromMap(t *testing.T) {
	m := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}

	ctx := FromMap(m)

	if v, ok := ctx["key1"]; !ok || v != "value1" {
		t.Errorf("expected key1=value1, got %v", v)
	}
	if v, ok := ctx["key2"]; !ok || v != 42 {
		t.Errorf("expected key2=42, got %v", v)
	}
}

func TestFromQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/?name=test&ids=1&ids=2", nil)

	ctx := FromQuery(c)

	if v, ok := ctx["name"]; !ok || v != "test" {
		t.Errorf("expected name=test, got %v", v)
	}

	if v, ok := ctx["ids"]; !ok {
		t.Errorf("expected ids to exist")
	} else {
		ids, ok := v.([]string)
		if !ok {
			t.Errorf("expected ids to be []string, got %T", v)
		} else if len(ids) != 2 || ids[0] != "1" || ids[1] != "2" {
			t.Errorf("expected ids=[1,2], got %v", ids)
		}
	}
}

func TestContextSet(t *testing.T) {
	ctx := make(Context)
	result := ctx.Set("key", "value")

	// Verify chaining works by checking the result has the value
	if v, ok := result["key"]; !ok || v != "value" {
		t.Error("Set should return the same context for chaining")
	}
	if v, ok := ctx["key"]; !ok || v != "value" {
		t.Errorf("expected key=value, got %v", v)
	}
}

func TestContextHas(t *testing.T) {
	ctx := Context{"key": "value"}

	if !ctx.Has("key") {
		t.Error("expected Has(key) to return true")
	}
	if ctx.Has("nonexistent") {
		t.Error("expected Has(nonexistent) to return false")
	}
}

func TestContextGet(t *testing.T) {
	ctx := Context{"key": "value"}

	v, ok := ctx.Get("key")
	if !ok || v != "value" {
		t.Errorf("expected (value, true), got (%v, %v)", v, ok)
	}

	v, ok = ctx.Get("nonexistent")
	if ok || v != nil {
		t.Errorf("expected (nil, false), got (%v, %v)", v, ok)
	}
}

func TestContextGetString(t *testing.T) {
	ctx := Context{"str": "hello", "notStr": 42}

	s, ok := ctx.GetString("str")
	if !ok || s != "hello" {
		t.Errorf("expected (hello, true), got (%v, %v)", s, ok)
	}

	s, ok = ctx.GetString("notStr")
	if ok || s != "" {
		t.Errorf("expected (, false), got (%v, %v)", s, ok)
	}

	s, ok = ctx.GetString("nonexistent")
	if ok || s != "" {
		t.Errorf("expected (, false), got (%v, %v)", s, ok)
	}
}

func TestContextGetInt(t *testing.T) {
	ctx := Context{"num": 42, "notNum": "hello"}

	n, ok := ctx.GetInt("num")
	if !ok || n != 42 {
		t.Errorf("expected (42, true), got (%v, %v)", n, ok)
	}

	n, ok = ctx.GetInt("notNum")
	if ok || n != 0 {
		t.Errorf("expected (0, false), got (%v, %v)", n, ok)
	}
}

func TestContextGetFloat(t *testing.T) {
	ctx := Context{"num": 3.14, "notNum": "hello"}

	f, ok := ctx.GetFloat("num")
	if !ok || f != 3.14 {
		t.Errorf("expected (3.14, true), got (%v, %v)", f, ok)
	}

	f, ok = ctx.GetFloat("notNum")
	if ok || f != 0 {
		t.Errorf("expected (0, false), got (%v, %v)", f, ok)
	}
}

func TestContextGetBool(t *testing.T) {
	ctx := Context{"yes": true, "no": false, "notBool": "hello"}

	b, ok := ctx.GetBool("yes")
	if !ok || !b {
		t.Errorf("expected (true, true), got (%v, %v)", b, ok)
	}

	b, ok = ctx.GetBool("no")
	if !ok || b {
		t.Errorf("expected (false, true), got (%v, %v)", b, ok)
	}

	b, ok = ctx.GetBool("notBool")
	if ok || b {
		t.Errorf("expected (false, false), got (%v, %v)", b, ok)
	}
}

func TestContextGetStringSlice(t *testing.T) {
	ctx := Context{"slice": []string{"a", "b", "c"}, "notSlice": "hello"}

	s, ok := ctx.GetStringSlice("slice")
	if !ok || len(s) != 3 || s[0] != "a" {
		t.Errorf("expected ([a,b,c], true), got (%v, %v)", s, ok)
	}

	s, ok = ctx.GetStringSlice("notSlice")
	if ok || s != nil {
		t.Errorf("expected (nil, false), got (%v, %v)", s, ok)
	}
}

func TestContextChaining(t *testing.T) {
	ctx := make(Context).
		Set("a", 1).
		Set("b", 2).
		Set("c", 3)

	if len(ctx) != 3 {
		t.Errorf("expected 3 keys, got %d", len(ctx))
	}
}
