package scanner

import "testing"

// Every kind the walker can dispatch must have a handler. Before the
// dispatch table existed this was two switch statements linked by bare
// string literals: a mismatched literal compiled fine and silently
// dropped every file of that type, which in an exposure scan reads as
// "this machine is clean".
func TestEveryJobKindHasHandler(t *testing.T) {
	handlers := newParsers(0, nil, nil).handlers()
	for _, k := range allJobKinds {
		if _, ok := handlers[k]; !ok {
			t.Errorf("job kind %q has no registered handler", k)
		}
	}
	if len(handlers) != len(allJobKinds) {
		t.Errorf("handler table has %d entries but allJobKinds lists %d; a kind is registered but undeclared",
			len(handlers), len(allJobKinds))
	}
}

// A duplicated constant value would make two kinds collide in the
// handler map, so one parser would silently shadow the other.
func TestJobKindsAreUnique(t *testing.T) {
	seen := make(map[jobKind]bool, len(allJobKinds))
	for _, k := range allJobKinds {
		if k == "" {
			t.Error("empty job kind declared")
		}
		if seen[k] {
			t.Errorf("duplicate job kind %q", k)
		}
		seen[k] = true
	}
}
