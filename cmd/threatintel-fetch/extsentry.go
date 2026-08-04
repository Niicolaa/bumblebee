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
	extSentryURL  = "https://raw.githubusercontent.com/ExtSentry/ExtSentry.github.io/main/feeds/extsentry_ioc_feed.csv"
	extSentryRepo = "https://github.com/ExtSentry/ExtSentry.github.io"
	// Feed is ~few hundred KB today (~2k indicators). Cap at 16 MB.
	extSentryMaxBytes = 16 * 1024 * 1024
)

// fetchExtSentry pulls ExtSentry's IOC feed and converts it to a
// browser-extension exposure catalog. ExtSentry rebuilds hourly from
// mthcht/awesome-lists, but enriches rows with per-extension severity,
// category, threat_type, and CRX SHA256 — fields the upstream raw lists
// don't carry — which is why we consume the ExtSentry CSV instead of
// the raw mthcht list.
//
// CSV schema:
//
//	extension_id,extension_name,wildcard_pattern,category,threat_type,
//	reference_url,description,chrome_webstore_url,severity,crx_sha256,
//	first_seen,feed_source
//
// We treat any row with threat_type=malicious|suspicious as an entry;
// rows the feed marks as benign (if any are ever emitted) are skipped.
func fetchExtSentry(ctx context.Context, source string) (*catalog, error) {
	body, err := readSource(ctx, source, extSentryMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("fetch extsentry: %w", err)
	}
	body = bytes.TrimPrefix(body, utf8BOM)
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse extsentry CSV: %w", err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("parse extsentry CSV: no rows")
	}
	header := rows[0]
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(h)] = i
	}
	required := []string{"extension_id", "category", "threat_type"}
	for _, k := range required {
		if _, ok := col[k]; !ok {
			return nil, fmt.Errorf("parse extsentry CSV: missing column %q", k)
		}
	}

	seen := map[string]bool{}
	out := &catalog{
		SchemaVersion: model.SchemaVersion,
		Comment:       "ExtSentry malicious/suspicious browser extension IDs (rebuilt hourly from mthcht/awesome-lists with per-row severity, category, and CRX hashes). Auto-generated; do not hand-edit. Each entry uses versions=[\"*\"] because Chrome auto-updates extensions and the extension ID is the IOC.",
		Source:        extSentryRepo,
		GeneratedUTC:  time.Now().UTC().Format(time.RFC3339),
	}
	for _, row := range rows[1:] {
		if len(row) < len(header) {
			continue
		}
		extID := strings.TrimSpace(row[col["extension_id"]])
		if extID == "" || !isChromeExtensionID(extID) {
			continue
		}
		threat := strings.ToLower(strings.TrimSpace(row[col["threat_type"]]))
		if threat != "malicious" && threat != "suspicious" {
			// Defensive: future-proof against benign rows ever showing up.
			continue
		}
		if seen[extID] {
			continue
		}
		seen[extID] = true

		category := strings.TrimSpace(row[col["category"]])
		sev := getCol(row, col, "severity")
		if sev == "" {
			sev = severityFromExtSentry(category, threat)
		}

		ind := map[string]any{
			"extension_id": extID,
			"category":     category,
			"threat_type":  threat,
		}
		copyIfPresent(row, col, ind, "reference_url", "reference")
		copyIfPresent(row, col, ind, "description", "description")
		copyIfPresent(row, col, ind, "chrome_webstore_url", "chrome_webstore_url")
		copyIfPresent(row, col, ind, "crx_sha256", "crx_sha256")
		copyIfPresent(row, col, ind, "feed_source", "upstream_source")
		// Deliberately NOT copying upstream's `first_seen`: it carries the
		// feed's rebuild date, not the date the extension was first
		// observed. ExtSentry rebuilds hourly, so every row's value rolls
		// forward daily — every entry in this catalog churned on
		// 2026-08-04 for that reason alone. Storing it would rewrite the
		// whole ~1.4 MB file every day while telling an analyst nothing.

		name := strings.TrimSpace(getCol(row, col, "extension_name"))
		display := extID
		if name != "" {
			display = name + " (" + extID + ")"
		}

		out.Entries = append(out.Entries, &entry{
			ID:         "extsentry-" + extID,
			Name:       display,
			Ecosystem:  model.EcosystemBrowserExtension,
			Package:    extID,
			Versions:   []string{"*"},
			Severity:   strings.ToLower(sev),
			Source:     extSentryRepo,
			Indicators: ind,
		})
	}
	return out, nil
}

// severityFromExtSentry is the fallback when the upstream `severity`
// column is empty. `threat_type=suspicious` → medium (lower-confidence
// tier); malicious + category mapping mirrors malext-sentry buckets.
func severityFromExtSentry(category, threat string) string {
	if threat == "suspicious" {
		return "medium"
	}
	c := strings.ToLower(category)
	switch {
	case strings.Contains(c, "malware"),
		strings.Contains(c, "stealer"),
		strings.Contains(c, "credential"),
		strings.Contains(c, "spyware"),
		strings.Contains(c, "phish"):
		return "critical"
	case strings.Contains(c, "scam"),
		strings.Contains(c, "cryptocurrency"),
		strings.Contains(c, "compromised"),
		strings.Contains(c, "rmm"),
		strings.Contains(c, "proxy"),
		strings.Contains(c, "vpn"),
		strings.Contains(c, "password"):
		return "high"
	case strings.Contains(c, "pup"),
		strings.Contains(c, "defense evasion"):
		return "medium"
	default:
		return "high"
	}
}

func getCol(row []string, col map[string]int, name string) string {
	i, ok := col[name]
	if !ok || i >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[i])
}
