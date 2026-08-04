package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	"github.com/perplexityai/bumblebee/internal/model"
)

const (
	malExtSentryURL  = "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/refs/heads/main/malicious_extensions_detailed.csv"
	malExtSentryRepo = "https://github.com/toborrm9/malicious_extension_sentry"
	// CSV is ~few hundred KB today; 16 MB leaves plenty of headroom
	// without enabling a runaway download.
	malExtSentryMaxBytes = 16 * 1024 * 1024
)

// fetchMalExtSentry pulls the MalExt Sentry Chrome-extensions CSV and
// converts it to a bumblebee exposure catalog. Each row becomes one
// browser-extension entry with versions=["*"] (the extension ID is the
// IOC; Chrome auto-updates extensions, so any installed version is
// dangerous if the publisher is compromised or the extension was
// pulled for malware).
//
// CSV schema: extension_id,name,reason,source,insert_date_fmt,blocklist
func fetchMalExtSentry(ctx context.Context, source string) (*catalog, error) {
	body, err := readSource(ctx, source, malExtSentryMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("fetch malext-sentry: %w", err)
	}
	body = bytes.TrimPrefix(body, utf8BOM)
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1 // tolerate trailing-empty-column variance
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse malext-sentry CSV: %w", err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("parse malext-sentry CSV: no rows")
	}
	header := rows[0]
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(h)] = i
	}
	required := []string{"extension_id", "name", "reason", "source", "insert_date_fmt"}
	for _, k := range required {
		if _, ok := col[k]; !ok {
			return nil, fmt.Errorf("parse malext-sentry CSV: missing column %q (header=%v)", k, header)
		}
	}

	seen := map[string]bool{}
	out := &catalog{
		SchemaVersion: model.SchemaVersion,
		Comment:       "MalExt Sentry malicious browser extension IDs. Auto-generated; do not hand-edit. Each entry uses versions=[\"*\"] because Chrome auto-updates extensions and the extension ID is the IOC.",
		Source:        malExtSentryRepo,
		GeneratedUTC:  time.Now().UTC().Format(time.RFC3339),
	}
	for i, row := range rows[1:] {
		if len(row) < len(header) {
			continue
		}
		extID := strings.TrimSpace(row[col["extension_id"]])
		if extID == "" {
			continue
		}
		// Chrome extension IDs are exactly 32 lowercase a-p chars;
		// skip anything malformed rather than emit junk entries.
		if !isChromeExtensionID(extID) {
			continue
		}
		if seen[extID] {
			continue
		}
		seen[extID] = true

		name := strings.TrimSpace(row[col["name"]])
		reason := strings.TrimSpace(row[col["reason"]])
		src := strings.TrimSpace(row[col["source"]])
		insertDate := strings.TrimSpace(row[col["insert_date_fmt"]])

		out.Entries = append(out.Entries, &entry{
			ID:        "malext-sentry-" + extID,
			Name:      strings.TrimSpace(strings.Join([]string{name, "(" + reason + ")"}, " ")),
			Ecosystem: model.EcosystemBrowserExtension,
			Package:   extID,
			Versions:  []string{"*"},
			Severity:  severityFromReason(reason),
			Source:    malExtSentryRepo,
			Indicators: map[string]any{
				"extension_id":         extID,
				"reason":               reason,
				"upstream_source":      src,
				"upstream_insert_date": insertDate,
				"row_index":            i + 1,
			},
		})
	}
	return out, nil
}

func isChromeExtensionID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if c < 'a' || c > 'p' {
			return false
		}
	}
	return true
}

// severityFromReason maps free-form upstream "reason" strings to the
// rough severity buckets bumblebee uses. Unknown reasons fall back to
// "high" — an entry made it onto an upstream blocklist; if we can't
// classify the cause, lean cautious rather than down-rank it to info.
func severityFromReason(reason string) string {
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "malware"):
		return "critical"
	case strings.Contains(r, "spyware"), strings.Contains(r, "stealer"), strings.Contains(r, "phish"):
		return "critical"
	case strings.Contains(r, "policy violation"):
		return "medium"
	case strings.Contains(r, "bundling"), strings.Contains(r, "unwanted"):
		return "high"
	case strings.Contains(r, "scareware"):
		return "high"
	case r == "":
		return "high"
	default:
		return "high"
	}
}
