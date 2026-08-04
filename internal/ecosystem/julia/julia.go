// Package julia scans Julia `Manifest.toml` files.
//
// Two manifest generations exist. Format 2.0 groups entries under a
// `deps` table:
//
//	[[deps.ArgTools]]
//	uuid = "0dad84c5-..."
//	version = "1.1.1"
//
// Format 1.0 puts them at the top level as `[[ArgTools]]`. Both are
// handled; an entry is recognised by carrying a `uuid`, which
// distinguishes package entries from the manifest's own scalar metadata
// (`julia_version`, `manifest_format`).
//
// Standard-library packages are pinned to the Julia release and carry a
// uuid but no version; they are skipped rather than emitted without one.
package julia

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

const Ecosystem = model.EcosystemJulia

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsManifestTOML(base string) bool { return base == "Manifest.toml" }

func (s *Scanner) ScanManifestTOML(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	root, err := toml.Parse(data)
	if err != nil {
		s.note(path, "unparseable Manifest.toml: "+err.Error())
		return nil
	}
	// Format 2.0 nests entries under [deps]; format 1.0 has them at the
	// top level alongside scalar metadata keys.
	entries := root
	if deps, ok := toml.Table(root["deps"]); ok {
		entries = deps
	}
	projectPath := filepath.Dir(path)
	for name, value := range entries {
		for _, entry := range toml.Tables(value) {
			if uuid, _ := toml.String(entry["uuid"]); uuid == "" {
				continue
			}
			version, _ := toml.String(entry["version"])
			if version == "" {
				// A stdlib package tracks the Julia release itself.
				continue
			}
			r := base
			r.Ecosystem = Ecosystem
			r.PackageName = name
			r.NormalizedName = strings.ToLower(name)
			r.Version = version
			r.ProjectPath = projectPath
			r.PackageManager = "pkg"
			r.SourceType = "julia-manifest"
			r.SourceFile = path
			r.Confidence = "high"
			s.Emit(r)
		}
	}
	return nil
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
