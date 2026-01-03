package hook

import "testing"

func TestHookConstants(t *testing.T) {
	tests := []struct {
		name     string
		hook     Hook
		expected string
	}{
		{"Hook_Init", Hook_Init, "init"},
		{"Hook_BeforeStart", Hook_BeforeStart, "before_start"},
		{"Hook_Start", Hook_Start, "start"},
		{"Hook_Shutdown", Hook_Shutdown, "shutdown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.hook) != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.hook)
			}
		})
	}
}

func TestHookType(t *testing.T) {
	var h Hook = "custom_hook"
	if string(h) != "custom_hook" {
		t.Errorf("expected custom_hook, got %s", h)
	}
}
