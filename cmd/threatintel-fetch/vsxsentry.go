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
	vsxSentryURL  = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/VSCODE%20Extensions/feeds/vsxsentry_malicious_feed.csv"
	vsxSentryRepo = "https://github.com/mthcht/awesome-lists/tree/main/Lists/VSCODE%20Extensions"
	// CSV is currently ~few hundred KB; cap generously.
	vsxSentryMaxBytes = 16 * 1024 * 1024
)

// fetchVSXSentry pulls VSXSentry's malicious-only VS Code extension
// feed and converts it to an editor-extension exposure catalog.
//
// CSV schema:
//
//	extension_id,publisher_id,extension_name,metadata_comment,
//	metadata_severity,metadata_category,metadata_source,
//	metadata_reference,metadata_status,removal_date,source_reason,
//	last_updated_utc,merged_sources
//
// The `extension_id` column already follows bumblebee's
// editor-extension normalization (`<publisher>.<name>` lowercased),
// matching internal/ecosystem/editorext.
func fetchVSXSentry(ctx context.Context, source string) (*catalog, error) {
	body, err := readSource(ctx, source, vsxSentryMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("fetch vsxsentry: %w", err)
	}
	body = bytes.TrimPrefix(body, utf8BOM)
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse vsxsentry CSV: %w", err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("parse vsxsentry CSV: no rows")
	}
	header := rows[0]
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(h)] = i
	}
	required := []string{"extension_id", "metadata_severity", "metadata_category"}
	for _, k := range required {
		if _, ok := col[k]; !ok {
			return nil, fmt.Errorf("parse vsxsentry CSV: missing column %q", k)
		}
	}

	seen := map[string]bool{}
	out := &catalog{
		SchemaVersion: model.SchemaVersion,
		Comment:       "VSXSentry malicious VS Code extension IDs (mthcht/awesome-lists). Auto-generated; do not hand-edit. Each entry uses versions=[\"*\"] because editor extensions auto-update from the marketplace; once an ID is on the malicious list, any installed version is suspect.",
		Source:        vsxSentryRepo,
		GeneratedUTC:  time.Now().UTC().Format(time.RFC3339),
	}
	for _, row := range rows[1:] {
		if len(row) < len(header) {
			continue
		}
		extID := strings.ToLower(strings.TrimSpace(row[col["extension_id"]]))
		if extID == "" || !strings.Contains(extID, ".") {
			continue
		}
		if seen[extID] {
			continue
		}
		seen[extID] = true

		sev := strings.ToLower(strings.TrimSpace(row[col["metadata_severity"]]))
		if sev == "" {
			sev = "high"
		}
		category := strings.TrimSpace(row[col["metadata_category"]])

		ind := map[string]any{
			"extension_id": extID,
			"category":     category,
		}
		copyIfPresent(row, col, ind, "metadata_comment", "comment")
		copyIfPresent(row, col, ind, "metadata_source", "upstream_source")
		copyIfPresent(row, col, ind, "metadata_reference", "reference")
		copyIfPresent(row, col, ind, "metadata_status", "status")
		copyIfPresent(row, col, ind, "removal_date", "removal_date")
		copyIfPresent(row, col, ind, "merged_sources", "merged_sources")

		nameField := ""
		if i, ok := col["extension_name"]; ok && i < len(row) {
			nameField = strings.TrimSpace(row[i])
		}
		display := extID
		if nameField != "" {
			display = nameField + " (" + extID + ")"
		}

		out.Entries = append(out.Entries, &entry{
			ID:         "vsxsentry-" + extID,
			Name:       display,
			Ecosystem:  model.EcosystemEditorExtension,
			Package:    extID,
			Versions:   []string{"*"},
			Severity:   sev,
			Source:     vsxSentryRepo,
			Indicators: ind,
		})
	}
	return out, nil
}

func copyIfPresent(row []string, col map[string]int, dst map[string]any, csvCol, outKey string) {
	i, ok := col[csvCol]
	if !ok || i >= len(row) {
		return
	}
	v := strings.TrimSpace(row[i])
	if v == "" {
		return
	}
	dst[outKey] = v
}
