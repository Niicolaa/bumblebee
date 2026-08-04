// Package cargo scans Rust dependency artifacts.
//
// `Cargo.lock` is the resolved dependency graph: every entry carries an
// exact name and version, so records are high confidence. Entries without
// a `source` field are path/workspace members rather than registry
// crates; they are emitted with a local install scope so receivers can
// tell a first-party workspace crate from a crates.io download.
//
// Note that `~/.cargo` is already a curated baseline root, so on a
// developer machine this parser also picks up the lock files vendored
// inside the registry cache.
package cargo

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/toml"
)

const Ecosystem = model.EcosystemCratesIO

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsCargoLock(base string) bool { return base == "Cargo.lock" }

func (s *Scanner) ScanCargoLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	root, err := toml.Parse(data)
	if err != nil {
		s.note(path, "unparseable Cargo.lock: "+err.Error())
		return nil
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})
	for _, pkg := range toml.Tables(root["package"]) {
		name, _ := toml.String(pkg["name"])
		version, _ := toml.String(pkg["version"])
		if name == "" || version == "" {
			continue
		}
		key := name + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = name
		r.NormalizedName = normalizeName(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "cargo"
		r.SourceType = "cargo-lock"
		r.SourceFile = path
		// A missing `source` means a path dependency or workspace member —
		// local code, not something fetched from a registry.
		if src, _ := toml.String(pkg["source"]); src == "" {
			r.InstallScope = "local"
		}
		r.Confidence = "high"
		s.Emit(r)
	}
	return nil
}

// normalizeName lowercases the crate name and folds '_' to '-'. crates.io
// treats the two separators as equivalent when checking for name
// collisions, which is also what typosquat catalogs key on.
func normalizeName(name string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "_", "-")
}

func (s *Scanner) note(path, msg string) {
	if s.Diag != nil {
		s.Diag("warn", path, msg)
	}
}

func (s *Scanner) readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if s.MaxFileSize > 0 && info.Size() > s.MaxFileSize {
		if s.Diag != nil {
			s.Diag("warn", path, fmt.Sprintf("skipping: size %d exceeds max %d", info.Size(), s.MaxFileSize))
		}
		return nil, fmt.Errorf("file %s exceeds max size %d", path, s.MaxFileSize)
	}
	return io.ReadAll(f)
}
