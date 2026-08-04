package main

import (
	"testing"

	"github.com/perplexityai/bumblebee/internal/exposure"
	"github.com/perplexityai/bumblebee/internal/model"
)

func TestRunSelftestSucceedsAndExitsZero(t *testing.T) {
	code := runSelftest([]string{"--quiet"})
	if code != 0 {
		t.Fatalf("runSelftest exit code = %d, want 0", code)
	}
}

// A new ecosystem parser that ships without a selftest fixture is a
// silent coverage hole: `bumblebee selftest` keeps passing on adopter
// machines while saying nothing about the new code path. The embedded
// catalog is the cheap proxy for fixture coverage, because every entry
// in it is asserted to match exactly once by the expected-findings
// count in runSelftest.
func TestSelftestCoversEverySupportedEcosystem(t *testing.T) {
	data, err := selftestFS.ReadFile("selftest/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := exposure.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	covered := make(map[string]bool, len(model.SupportedEcosystems()))
	for _, e := range catalog.Entries {
		covered[e.Ecosystem] = true
	}
	for _, eco := range model.SupportedEcosystems() {
		if !covered[eco] {
			t.Errorf("no selftest fixture/catalog entry for ecosystem %q; "+
				"add one under cmd/bumblebee/selftest/fixtures and bump expectedSelftestFindings", eco)
		}
	}
}

// The count in selftest.go must stay in step with the catalog, since
// every entry is written to match exactly one fixture record.
func TestExpectedSelftestFindingsMatchesCatalogSize(t *testing.T) {
	data, err := selftestFS.ReadFile("selftest/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := exposure.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Len() != expectedSelftestFindings {
		t.Errorf("catalog has %d entries but expectedSelftestFindings = %d",
			catalog.Len(), expectedSelftestFindings)
	}
}
