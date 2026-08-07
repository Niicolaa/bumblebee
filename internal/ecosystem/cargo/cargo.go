// Package cargo scans Rust dependency state.
//
// Sources:
//
//	Cargo.lock                            the resolved dependency graph
//	                                      for a project: exact versions
//	                                      for the whole tree
//	~/.cargo/registry/src/<idx>/<crate>-<version>/   the extracted
//	                                      registry cache — the crate
//	                                      source is on disk at that
//	                                      exact version
//
// Cargo.toml is not read: its `[dependencies]` are semver ranges, not
// resolved versions, so it cannot say which version is present.
package cargo

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/ecosystem/safeopen"
	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/toml"
)

const Ecosystem = model.EcosystemCargo

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsCargoLock(base string) bool { return base == "Cargo.lock" }

// ScanCargoLock parses a Cargo.lock. Both the v1 and v2/v3/v4 layouts
// use the same [[package]] tables with name and version keys; the
// versions differ only in how `dependencies` entries and checksums are
// written, neither of which is emitted.
func (s *Scanner) ScanCargoLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	doc, err := toml.Parse(data)
	if err != nil {
		return fmt.Errorf("parse Cargo.lock: %w", err)
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	for _, tbl := range doc.TablesNamed("package") {
		name := tbl.String("name")
		version := tbl.String("version")
		if name == "" {
			continue
		}
		key := name + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		// An entry with no `source` is a local path or workspace member,
		// not a crates.io crate; it still exists at that version on disk,
		// but it is not something a registry advisory can name.
		confidence := "high"
		if tbl.String("source") == "" {
			confidence = "medium"
		}
		if version == "" {
			confidence = "low"
		}

		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = name
		r.NormalizedName = normalizeCrate(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "cargo"
		r.SourceType = "cargo-lock"
		r.SourceFile = path
		r.Confidence = confidence
		s.Emit(r)
	}
	return nil
}

// IsRegistrySrcMarker returns (true, name, version, crateDir) if path is
// the Cargo.toml at the root of an extracted crate in the registry
// source cache:
//
//	~/.cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.203/Cargo.toml
//
// The directory name carries the authoritative name and version, so the
// manifest is used only as the marker file and is never parsed — a
// crate's own Cargo.toml lists semver ranges, not resolved versions.
// The crate name may itself contain hyphens, so the split is on the last
// hyphen followed by something version-shaped.
func IsRegistrySrcMarker(path string) (bool, string, string, string) {
	if filepath.Base(path) != "Cargo.toml" {
		return false, "", "", ""
	}
	crateDir := filepath.Dir(path)
	indexDir := filepath.Dir(crateDir)
	// Must sit directly under .../registry/src/<index>/<crate>-<version>/
	if filepath.Base(filepath.Dir(indexDir)) != "src" {
		return false, "", "", ""
	}
	if filepath.Base(filepath.Dir(filepath.Dir(indexDir))) != "registry" {
		return false, "", "", ""
	}
	name, version, ok := splitCrateDir(filepath.Base(crateDir))
	if !ok {
		return false, "", "", ""
	}
	return true, name, version, crateDir
}

func splitCrateDir(base string) (name, version string, ok bool) {
	i := strings.LastIndex(base, "-")
	for i > 0 {
		candidate := base[i+1:]
		if candidate != "" && candidate[0] >= '0' && candidate[0] <= '9' {
			return base[:i], candidate, true
		}
		i = strings.LastIndex(base[:i], "-")
	}
	return "", "", false
}

// ScanRegistrySrc emits a record for an extracted crate in the registry
// cache. Identity comes from the directory name, so no file is read.
func (s *Scanner) ScanRegistrySrc(path, name, version, crateDir string, base model.Record) error {
	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = name
	r.NormalizedName = normalizeCrate(name)
	r.Version = version
	r.ProjectPath = crateDir
	r.PackageManager = "cargo"
	r.SourceType = "cargo-registry-src"
	r.SourceFile = path
	r.Confidence = "high"
	s.Emit(r)
	return nil
}

// normalizeCrate lowercases and folds hyphens to underscores. crates.io
// treats the two as equivalent for uniqueness (serde-json and
// serde_json cannot both be registered), so an advisory naming one must
// match the other.
func normalizeCrate(name string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "-", "_")
}

func (s *Scanner) readBounded(path string) ([]byte, error) {
	f, _, err := safeopen.Regular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	limit := s.MaxFileSize
	if limit <= 0 {
		limit = 5 * 1024 * 1024
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) == limit {
		if s.Diag != nil {
			s.Diag("warn", path, "file exceeds max-file-size; not parsed")
		}
		return nil, errors.New("file exceeds max-file-size")
	}
	return data, nil
}
