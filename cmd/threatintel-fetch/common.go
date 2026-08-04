package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/perplexityai/bumblebee/internal/exposure"
	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/normalize"
)

// normalizePackageForID returns a slug-safe version of a package name
// suitable for embedding into a generated catalog entry ID. Mirrors the
// per-ecosystem normalization the scanner uses at match time so
// generated IDs remain stable across renames.
func normalizePackageForID(eco, name string) string {
	switch eco {
	case model.EcosystemPyPI:
		return normalize.PyPI(name)
	case model.EcosystemNPM:
		return normalize.NPM(name)
	default:
		return strings.ToLower(name)
	}
}

// encodeCatalog writes the catalog as JSON with the top-level metadata
// fields indented but each entry compacted onto a single line. This
// keeps the file small (one ~250-byte line per entry instead of ~15
// indented lines) so the OSV npm catalog stays well under GitHub's
// 100 MB file limit while still producing useful line-by-line diffs
// when entries are added or removed.
func encodeCatalog(c *catalog) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("{\n")
	buf.WriteString("  \"schema_version\": ")
	if err := writeJSON(&buf, c.SchemaVersion); err != nil {
		return nil, err
	}
	if c.Comment != "" {
		buf.WriteString(",\n  \"_comment\": ")
		if err := writeJSON(&buf, c.Comment); err != nil {
			return nil, err
		}
	}
	if c.GeneratedUTC != "" {
		buf.WriteString(",\n  \"_generated_utc\": ")
		if err := writeJSON(&buf, c.GeneratedUTC); err != nil {
			return nil, err
		}
	}
	if c.Source != "" {
		buf.WriteString(",\n  \"_source\": ")
		if err := writeJSON(&buf, c.Source); err != nil {
			return nil, err
		}
	}
	buf.WriteString(",\n  \"entries\": [")
	for i, e := range c.Entries {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString("\n    ")
		raw, err := compactJSON(e)
		if err != nil {
			return nil, fmt.Errorf("encode entry %s: %w", e.ID, err)
		}
		buf.Write(raw)
	}
	if len(c.Entries) > 0 {
		buf.WriteString("\n  ")
	}
	buf.WriteString("]\n}\n")
	return buf.Bytes(), nil
}

func writeJSON(buf *bytes.Buffer, v any) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	// json.Encoder appends a trailing newline; trim it so callers can
	// place the value mid-line.
	b := buf.Bytes()
	if n := len(b); n > 0 && b[n-1] == '\n' {
		buf.Truncate(n - 1)
	}
	return nil
}

func compactJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := b.Bytes()
	// strip trailing newline emitted by Encode
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}

// utf8BOM is the 3-byte UTF-8 byte-order mark some upstream CSVs ship
// with. Stripping it before csv.Reader prevents the first header cell
// from being parsed as a BOM-prefixed column name and missing the
// required-column lookup.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// generatedUTCLine matches the whole `_generated_utc` line, including
// its trailing newline, so it can be masked out of an equality check.
var generatedUTCLine = regexp.MustCompile(`(?m)^\s*"_generated_utc":\s*"[^"]*",?\n`)

// stripGeneratedUTC removes the provenance timestamp so two catalogs
// can be compared on content alone.
func stripGeneratedUTC(b []byte) []byte {
	return generatedUTCLine.ReplaceAll(b, nil)
}

// catalog is the on-disk JSON shape. It mirrors the exposure-loader
// schema and adds the optional `source` / `indicators` fields the
// hand-written campaign catalogs already use; the loader ignores
// unknown fields.
type catalog struct {
	SchemaVersion string   `json:"schema_version"`
	Comment       string   `json:"_comment,omitempty"`
	GeneratedUTC  string   `json:"_generated_utc,omitempty"`
	Source        string   `json:"_source,omitempty"`
	Entries       []*entry `json:"entries"`
}

type entry struct {
	ID         string         `json:"id"`
	Name       string         `json:"name,omitempty"`
	Ecosystem  string         `json:"ecosystem"`
	Package    string         `json:"package"`
	Versions   []string       `json:"versions"`
	Severity   string         `json:"severity,omitempty"`
	Source     string         `json:"source,omitempty"`
	Indicators map[string]any `json:"indicators,omitempty"`
}

// writeCatalog serialises entries to path. Entries are sorted by ID so
// daily reruns produce stable diffs. The file is written via temp +
// rename so partial writes never replace a known-good catalog. If the
// new bytes are byte-identical to the existing file the write is
// skipped (keeps mtime stable and the GH workflow a no-op when feeds
// haven't changed).
//
// The serialised catalog is round-tripped through exposure.Parse before
// it is written so a malformed entry can never overwrite a working
// catalog on disk.
func writeCatalog(path string, c *catalog) (changed bool, err error) {
	if c.SchemaVersion == "" {
		c.SchemaVersion = model.SchemaVersion
	}
	sort.SliceStable(c.Entries, func(i, j int) bool {
		return c.Entries[i].ID < c.Entries[j].ID
	})

	body, err := encodeCatalog(c)
	if err != nil {
		return false, err
	}

	if _, err := exposure.Parse(body); err != nil {
		return false, fmt.Errorf("self-validate %s: %w", path, err)
	}

	if existing, err := os.ReadFile(path); err == nil {
		if bytes.Equal(existing, body) {
			return false, nil
		}
		// `_generated_utc` moves on every run, so a naive byte compare
		// would report every catalog as changed every day and make the
		// sync job commit + cut a release on days when no feed actually
		// moved. Compare with that one line masked out; if the rest is
		// identical, keep the file (and its original timestamp) as-is.
		// The stamp then means "when this data last changed", which is
		// what a reader actually wants, rather than "when we last polled".
		if bytes.Equal(stripGeneratedUTC(existing), stripGeneratedUTC(body)) {
			return false, nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // safe no-op after a successful rename
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return false, err
	}
	return true, nil
}

// writeShardedCatalog partitions c.Entries by FNV32(package) % n and
// writes one file per shard at the supplied paths. Sharding keeps any
// single auto-* file under ~25 MB even as the npm OSV catalog grows
// past 200k entries, so daily updates touch a small subset and stay
// well under GitHub's 50 MB recommended file limit. Returns counts of
// shards that were actually rewritten (changed) and total entries.
func writeShardedCatalog(paths []string, c *catalog) (changedShards, totalEntries int, err error) {
	n := len(paths)
	if n <= 1 {
		return 0, 0, fmt.Errorf("writeShardedCatalog: need >=2 paths, got %d", n)
	}
	shards := make([]*catalog, n)
	for i := range shards {
		shards[i] = &catalog{
			SchemaVersion: c.SchemaVersion,
			Comment:       fmt.Sprintf("%s (shard %d/%d, partitioned by FNV32(package) %% %d)", c.Comment, i+1, n, n),
			GeneratedUTC:  c.GeneratedUTC,
			Source:        c.Source,
		}
	}
	for _, e := range c.Entries {
		h := fnv.New32a()
		h.Write([]byte(e.Package))
		idx := int(h.Sum32()) % n
		if idx < 0 {
			idx += n
		}
		shards[idx].Entries = append(shards[idx].Entries, e)
	}
	for i, p := range paths {
		changed, werr := writeCatalog(p, shards[i])
		if werr != nil {
			return changedShards, totalEntries, werr
		}
		if changed {
			changedShards++
		}
		totalEntries += len(shards[i].Entries)
	}
	return changedShards, totalEntries, nil
}

// shardPaths returns the N file paths for a sharded catalog. Names are
// stable (`auto-<base>-NN.json`) so sharded files diff cleanly against
// prior runs.
func shardPaths(outDir, base string, n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = filepath.Join(outDir, fmt.Sprintf("auto-%s-%02d.json", base, i))
	}
	return out
}

// httpGet downloads url with a hard cap on the response body size. The
// fetchers all pull bounded feeds (low MB range today, ~50 MB worst-
// case for the largest OSV ecosystem zip); the cap prevents a runaway
// download from filling memory if the upstream shape changes.
func httpGet(ctx context.Context, url string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "bumblebee-threatintel-fetch/1")
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("GET %s: body exceeded cap of %d bytes", url, maxBytes)
	}
	return body, nil
}

// readSource fetches a body from either http(s):// or a local file
// path. Tests use local-file paths to avoid live network calls.
func readSource(ctx context.Context, src string, maxBytes int64) ([]byte, error) {
	if isURL(src) {
		return httpGet(ctx, src, maxBytes)
	}
	body, err := os.ReadFile(src)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("read %s: body exceeded cap of %d bytes", src, maxBytes)
	}
	return body, nil
}

func isURL(s string) bool {
	return len(s) > 7 && (s[:7] == "http://" || s[:8] == "https://")
}
