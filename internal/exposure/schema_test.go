package exposure

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

// The published exposure-catalog schema enumerates the ecosystem values a
// catalog entry may carry. Nothing at runtime reads that file — the CI
// catalog check uses Load — so the enum can fall behind the scanner
// silently, and did: `homebrew` was added while `agent-skill` was not,
// and none of the ecosystems added later were present either. The result
// is a schema that rejects catalogs this repository itself generates.
//
// Keeping the two in lockstep here means adding an ecosystem constant
// fails this test until the schema is updated too.
func TestExposureCatalogSchemaEcosystemsMatchModel(t *testing.T) {
	const schemaPath = "../../docs/schema/v0.2.0/exposure-catalog.schema.json"
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Clean(schemaPath), err)
	}

	var doc struct {
		Properties struct {
			Entries struct {
				Items struct {
					Properties struct {
						Ecosystem struct {
							Enum []string `json:"enum"`
						} `json:"ecosystem"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"entries"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	enum := doc.Properties.Entries.Items.Properties.Ecosystem.Enum
	if len(enum) == 0 {
		t.Fatal("could not locate the ecosystem enum in the schema; has the schema shape changed?")
	}

	inSchema := make(map[string]bool, len(enum))
	for _, e := range enum {
		inSchema[e] = true
	}
	for _, e := range model.SupportedEcosystems() {
		if !inSchema[e] {
			t.Errorf("ecosystem %q is emitted by the scanner but missing from the catalog schema enum", e)
		}
	}

	supported := make(map[string]bool)
	for _, e := range model.SupportedEcosystems() {
		supported[e] = true
	}
	for _, e := range enum {
		if !supported[e] {
			t.Errorf("schema enum allows ecosystem %q, which the scanner never emits", e)
		}
	}
}
