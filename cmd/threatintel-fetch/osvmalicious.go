package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/osv"
)

const (
	osvBucketURL = "https://osv-vulnerabilities.storage.googleapis.com"
	// per-ecosystem all.zip files run from ~2 MB (Packagist) to ~200 MB
	// (npm, up from ~30 MB in 2024). 512 MB caps runaway growth while
	// leaving headroom for npm's continued expansion.
	osvMaxBytes = 512 * 1024 * 1024
	// per-record json cap; matches upstream tools/osvcatalog default.
	osvPerRecordMaxBytes = 5 * 1024 * 1024
)

// osvEcosystem maps the bumblebee ecosystem constant to the
// capitalization OSV uses in URLs (and in the affected.package.ecosystem
// field).
type osvEcosystem struct {
	bumblebee string
	osv       string
}

var osvEcosystems = []osvEcosystem{
	{bumblebee: model.EcosystemNPM, osv: "npm"},
	{bumblebee: model.EcosystemPyPI, osv: "PyPI"},
	{bumblebee: model.EcosystemGo, osv: "Go"},
	{bumblebee: model.EcosystemRubyGems, osv: "RubyGems"},
	{bumblebee: model.EcosystemPackagist, osv: "Packagist"},
	// OSV's "VSCode" ecosystem carries `publisher.name` marketplace ids,
	// which internal/osv already maps to bumblebee's editor-extension.
	{bumblebee: model.EcosystemEditorExtension, osv: "VSCode"},
}

// osvShardCount marks ecosystems whose unshard'd auto-* catalog would
// exceed GitHub's 50 MB recommended file size. Sharded ecosystems emit
// `auto-osv-malicious-<eco>-NN.json` instead of a single monolithic file.
// Picking 4 shards keeps each file at ~20 MB today with headroom for
// growth before any single shard crosses 50 MB.
var osvShardCount = map[string]int{
	model.EcosystemNPM: 4,
}

// fetchOSVMalicious pulls the per-ecosystem OSV `all.zip`, filters for
// MAL-* advisories (the malicious-packages namespace populated by
// ossf/malicious-packages and curated by Google), and delegates the
// record→catalog conversion to internal/osv — the same converter
// upstream ships as tools/osvcatalog. Our fetcher just does I/O and
// wraps the result in the file layout writeCatalog understands.
//
// If `source` is a URL, the per-ecosystem all.zip is fetched from
// osv-vulnerabilities.storage.googleapis.com; if `source` is a local
// path, it's treated as a directory containing `{osvName}/all.zip`
// for fixture-driven tests.
func fetchOSVMalicious(ctx context.Context, eco osvEcosystem, source string) (*catalog, error) {
	var body []byte
	var err error
	if source == "" || isURL(source) {
		url := osvBucketURL
		if source != "" {
			url = strings.TrimRight(source, "/")
		}
		url = url + "/" + eco.osv + "/all.zip"
		body, err = httpGet(ctx, url, osvMaxBytes)
		if err != nil {
			return nil, fmt.Errorf("fetch OSV %s: %w", eco.osv, err)
		}
	} else {
		body, err = readSource(ctx, source+"/"+eco.osv+"/all.zip", osvMaxBytes)
		if err != nil {
			return nil, err
		}
	}

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("open OSV zip for %s: %w", eco.osv, err)
	}

	var records []osv.Record
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		base := f.Name
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		// Skip obvious non-MAL records at the zip level to keep the
		// json unmarshal count down; the converter re-checks via
		// isMalicious() so aliased-to-MAL records still get in via
		// records whose filename isn't MAL- but whose id/aliases are.
		if !strings.HasPrefix(base, "MAL-") {
			continue
		}
		rec, err := readOSVRecord(f)
		if err != nil {
			// One bad record shouldn't poison the whole catalog.
			continue
		}
		records = append(records, *rec)
	}

	entries, _ := osv.Convert(records, osv.Options{
		Ecosystems: map[string]bool{eco.bumblebee: true},
		Source:     osvBucketURL + "/" + eco.osv + "/all.zip",
	})

	out := &catalog{
		SchemaVersion: model.SchemaVersion,
		Comment:       "OSV malicious-packages MAL-* advisories for the " + eco.bumblebee + " ecosystem (ossf/malicious-packages, mirrored via osv.dev). Auto-generated; do not hand-edit. Conversion via internal/osv (same as tools/osvcatalog).",
		Source:        "https://github.com/ossf/malicious-packages",
		GeneratedUTC:  time.Now().UTC().Format(time.RFC3339),
	}
	for _, e := range entries {
		out.Entries = append(out.Entries, &entry{
			ID:        e.ID,
			Name:      e.Name,
			Ecosystem: e.Ecosystem,
			Package:   e.Package,
			Versions:  e.Versions,
			Severity:  e.Severity,
			Source:    e.Source,
		})
	}
	return out, nil
}

func readOSVRecord(f *zip.File) (*osv.Record, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	body, err := io.ReadAll(io.LimitReader(rc, osvPerRecordMaxBytes))
	if err != nil {
		return nil, err
	}
	var rec osv.Record
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}
