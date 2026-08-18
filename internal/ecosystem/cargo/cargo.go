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

	"github.com/pelletier/go-toml/v2"
	"github.com/perplexityai/bumblebee/internal/ecosystem/safeopen"
	"github.com/perplexityai/bumblebee/internal/model"
)

const Ecosystem = model.EcosystemCargo

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsCargoLock(base string) bool { return base == "Cargo.lock" }

// cargoLock is Cargo.lock's structure. Only the fields used are
// declared; v1's [metadata] table (quoted keys containing dots) and the
// per-package checksum/dependencies are left undecoded.
//
// Source is a plain string here. It is deliberately NOT shared with the
// Python lock structs: uv.lock spells the same key as an inline table
// (`source = { registry = "..." }`), and one struct serving both would
// fail to decode one of them and drop the entire file.
type cargoLock struct {
	Package []cargoPackage `toml:"package"`
}

type cargoPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	Source  string `toml:"source"`
}

// ScanCargoLock parses a Cargo.lock. The v1 and v2/v3/v4 layouts differ
// only in how checksums and `dependencies` entries are written, neither
// of which is emitted, so one decode covers all of them.
func (s *Scanner) ScanCargoLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var doc cargoLock
	if err := toml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse Cargo.lock: %w", err)
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	for _, p := range doc.Package {
		name := strings.TrimSpace(p.Name)
		version := strings.TrimSpace(p.Version)
		if name == "" {
			continue
		}
		key := name + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		// An entry with no `source` is a workspace member or path
		// dependency, not a crates.io crate; it exists at that version on
		// disk, but no registry advisory can name it.
		confidence := "high"
		if strings.TrimSpace(p.Source) == "" {
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
