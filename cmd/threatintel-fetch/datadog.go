package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/perplexityai/bumblebee/internal/model"
)

const (
	dataDogRepo = "https://github.com/DataDog/malicious-software-packages-dataset"
	// per-ecosystem manifest sizes: ~few hundred KB to low MB today,
	// well under the 16 MB cap.
	dataDogMaxBytes = 16 * 1024 * 1024
)

// dataDogEcosystem maps the bumblebee ecosystem to the path segment
// DataDog uses in their dataset (samples/<segment>/manifest.json).
type dataDogEcosystem struct {
	bumblebee string
	datadog   string
}

var dataDogEcosystems = []dataDogEcosystem{
	{bumblebee: model.EcosystemNPM, datadog: "npm"},
	{bumblebee: model.EcosystemPyPI, datadog: "pypi"},
}

// dataDogManifestURL returns the raw URL for one ecosystem's manifest.
func dataDogManifestURL(ds string) string {
	return "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/" + ds + "/manifest.json"
}

// fetchDataDog pulls one DataDog dataset manifest and converts it to a
// bumblebee exposure catalog. The manifest is a flat object of
// `package_name -> null | [version, ...]`. `null` means the package
// itself is considered malicious (no version distinction); a version
// array narrows the exposure to those versions only.
//
// DataDog identifies these via their GuardDog static-analysis tool,
// which is an independent detector relative to OSV/ossf
// malicious-packages, so there is real additive coverage even where
// the two feeds overlap.
func fetchDataDog(ctx context.Context, eco dataDogEcosystem, source string) (*catalog, error) {
	var url string
	if source == "" {
		url = dataDogManifestURL(eco.datadog)
	} else if isURL(source) {
		url = strings.TrimRight(source, "/") + "/" + eco.datadog + "/manifest.json"
	} else {
		url = source + "/" + eco.datadog + "/manifest.json"
	}
	body, err := readSource(ctx, url, dataDogMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("fetch datadog %s: %w", eco.datadog, err)
	}

	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("parse datadog %s manifest: %w", eco.datadog, err)
	}

	out := &catalog{
		SchemaVersion: model.SchemaVersion,
		Comment:       "DataDog malicious-software-packages-dataset (" + eco.datadog + ") — packages flagged by Datadog's GuardDog static-analysis pipeline. Auto-generated; do not hand-edit. Entries with versions=[\"*\"] correspond to manifest values of null (whole package malicious).",
		Source:        dataDogRepo,
		GeneratedUTC:  time.Now().UTC().Format(time.RFC3339),
	}

	for pkg, raw := range manifest {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			continue
		}
		versions := []string{"*"}
		if len(raw) > 0 && string(raw) != "null" {
			var vs []string
			if err := json.Unmarshal(raw, &vs); err != nil {
				// Unexpected shape — keep going, wildcard the package.
				vs = nil
			}
			cleaned := cleanVersionList(vs)
			if len(cleaned) > 0 {
				versions = cleaned
			}
		}

		out.Entries = append(out.Entries, &entry{
			ID:        "datadog-" + eco.datadog + "--" + normalizePackageForID(eco.bumblebee, pkg),
			Name:      "DataDog GuardDog flagged " + eco.datadog + " package " + pkg,
			Ecosystem: eco.bumblebee,
			Package:   pkg,
			Versions:  versions,
			Severity:  "critical",
			Source:    dataDogRepo,
			Indicators: map[string]any{
				"upstream_source": "datadog/malicious-software-packages-dataset",
				"manifest_ref":    dataDogManifestURL(eco.datadog),
			},
		})
	}
	return out, nil
}

func cleanVersionList(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
