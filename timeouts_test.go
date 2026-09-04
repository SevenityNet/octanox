package octanox

import (
	"testing"
	"time"
)

func TestTimeoutEnvOverridesAppValue(t *testing.T) {
	t.Setenv("NOX__TEST_TIMEOUT", "7")
	tm := newTimeout("NOX__TEST_TIMEOUT", 30*time.Second)
	tm.value = 5 * time.Second
	if got := tm.effective(); got != 7*time.Second {
		t.Fatalf("effective = %v, want the 7s env override", got)
	}
}

func TestTimeoutFallsBackToAppValueWhenEnvUnsetOrInvalid(t *testing.T) {
	for _, raw := range []string{"", "abc", "0", "-3"} {
		t.Setenv("NOX__TEST_TIMEOUT", raw)
		tm := newTimeout("NOX__TEST_TIMEOUT", 30*time.Second)
		if got := tm.effective(); got != 30*time.Second {
			t.Fatalf("env %q: effective = %v, want the 30s default", raw, got)
		}
		tm.value = 9 * time.Second
		if got := tm.effective(); got != 9*time.Second {
			t.Fatalf("env %q: effective = %v, want the 9s app value", raw, got)
		}
	}
}

func TestSettersApplyAfterNewUnlessEnvSet(t *testing.T) {
	t.Setenv("NOX__BODY_DRAIN_GRACE", "4")
	previous := Current
	Current = nil
	t.Cleanup(func() { Current = previous })

	app := New().SetBodyIdleTimeout(11 * time.Second).SetBodyDrainGrace(1 * time.Second)
	if got := app.bodyIdleTimeout.effective(); got != 11*time.Second {
		t.Fatalf("body idle = %v, want the 11s setter value", got)
	}
	if got := app.bodyDrainGrace.effective(); got != 4*time.Second {
		t.Fatalf("drain grace = %v, want the 4s env override", got)
	}
}
