package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/perplexityai/bumblebee/internal/exposure"
)

// snapshotCounts records the entry count of every *.json in dir. Files
// that don't parse are omitted rather than erroring: a catalog that was
// already broken before this run shouldn't block the run that might fix
// it.
func snapshotCounts(dir string) map[string]int {
	out := map[string]int{}
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return out
	}
	for _, p := range matches {
		body, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		cat, err := exposure.Parse(body)
		if err != nil {
			continue
		}
		out[filepath.Base(p)] = cat.Len()
	}
	return out
}

// checkShrink compares post-fetch entry counts against the pre-fetch
// snapshot and reports catalogs that lost too large a fraction of their
// entries. This is the safety net for publishing straight to main
// without a human reviewing a PR diff: an upstream that renames a CSV
// column or serves an error page yields a catalog that parses fine but
// is empty or near-empty, and would otherwise silently ship.
//
// Only files present in `before` are checked — a brand-new catalog has
// nothing to shrink from. minRatio <= 0 disables the check entirely.
func checkShrink(dir string, before map[string]int, minRatio float64) []string {
	if minRatio <= 0 {
		return nil
	}
	after := snapshotCounts(dir)

	var names []string
	for name := range before {
		names = append(names, name)
	}
	sort.Strings(names)

	var violations []string
	for _, name := range names {
		prev := before[name]
		if prev == 0 {
			// Nothing to compare against; an empty catalog growing is fine.
			continue
		}
		now, stillPresent := after[name]
		if !stillPresent {
			violations = append(violations, fmt.Sprintf(
				"%s disappeared or no longer parses (had %d entries)", name, prev))
			continue
		}
		if float64(now) < float64(prev)*minRatio {
			violations = append(violations, fmt.Sprintf(
				"%s shrank from %d to %d entries (%.1f%% of previous, floor is %.0f%%)",
				name, prev, now, 100*float64(now)/float64(prev), 100*minRatio))
		}
	}
	return violations
}
