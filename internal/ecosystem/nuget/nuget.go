// Package nuget scans .NET package state.
//
// Sources, in descending order of what they prove:
//
//	~/.nuget/packages/<id>/<version>/    the global package cache — the
//	                                     direct analogue of site-packages
//	                                     or node_modules: the package is
//	                                     on disk at that exact version.
//	packages.lock.json                   resolved lock for a project
//	packages.config                      legacy (pre-PackageReference)
//	                                     project dependency list
//
// `*.deps.json` is deliberately NOT read. It is the runtime dependency
// graph emitted next to a *built* application, which answers "what
// shipped" — the SBOM question bumblebee explicitly does not try to
// answer — and on a developer machine it duplicates the cache entries
// with worse provenance.
//
// Package identity is case-insensitive on NuGet, and the cache stores
// ids lowercased, so records normalise to lowercase.
package nuget

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

const Ecosystem = model.EcosystemNuGet

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsPackagesLockJSON(base string) bool { return base == "packages.lock.json" }
func IsPackagesConfig(base string) bool   { return base == "packages.config" }

// IsCacheNuspec returns (true, id, version, packageDir) if path is the
// .nuspec at the root of a global-cache package directory:
//
//	~/.nuget/packages/newtonsoft.json/13.0.3/newtonsoft.json.nuspec
//
// The directory layout carries the authoritative id and version, so the
// nuspec is used only as the marker file — its XML is never read. That
// keeps a cache sweep to one cheap path check per candidate instead of
// an XML parse of every package on the machine.
func IsCacheNuspec(path string) (bool, string, string, string) {
	if !strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".nuspec") {
		return false, "", "", ""
	}
	versionDir := filepath.Dir(path)
	idDir := filepath.Dir(versionDir)
	version := filepath.Base(versionDir)
	id := filepath.Base(idDir)
	if version == "." || id == "." || version == string(filepath.Separator) {
		return false, "", "", ""
	}
	// The marker file is <id>.nuspec, which is what distinguishes a cache
	// root from a nuspec that happens to live inside a package's content.
	if !strings.EqualFold(filepath.Base(path), id+".nuspec") {
		return false, "", "", ""
	}
	// A version directory always starts with a digit; this rejects
	// lib/net8.0/foo.nuspec style false matches.
	if version == "" || version[0] < '0' || version[0] > '9' {
		return false, "", "", ""
	}
	return true, id, version, versionDir
}

// ScanCachePackage emits one record for a global-cache package. Identity
// comes from the directory layout, so nothing is read from disk here.
func (s *Scanner) ScanCachePackage(path, id, version, packageDir string, base model.Record) error {
	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = id
	r.NormalizedName = strings.ToLower(id)
	r.Version = version
	r.ProjectPath = packageDir
	r.PackageManager = "nuget"
	r.SourceType = "nuget-global-cache"
	r.SourceFile = path
	r.Confidence = "high"
	s.Emit(r)
	return nil
}

type packagesLock struct {
	Version      int                                     `json:"version"`
	Dependencies map[string]map[string]packagesLockEntry `json:"dependencies"`
}

type packagesLockEntry struct {
	Type     string `json:"type"`
	Resolved string `json:"resolved"`
}

// ScanPackagesLockJSON parses a packages.lock.json. The file groups
// dependencies by target framework; the same package usually appears
// under several targets at the same version, so records are deduped on
// (id, version).
func (s *Scanner) ScanPackagesLockJSON(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var lock packagesLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("parse packages.lock.json: %w", err)
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	for _, byPackage := range lock.Dependencies {
		for id, entry := range byPackage {
			version := entry.Resolved
			confidence := "medium"
			if version == "" {
				// A project reference has no resolved registry version.
				confidence = "low"
			}
			key := strings.ToLower(id) + "\x00" + version
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}

			r := base
			r.Ecosystem = Ecosystem
			r.PackageName = id
			r.NormalizedName = strings.ToLower(id)
			r.Version = version
			r.ProjectPath = projectPath
			r.PackageManager = "nuget"
			r.SourceType = "nuget-packages-lock-json"
			r.SourceFile = path
			r.Confidence = confidence
			s.Emit(r)
		}
	}
	return nil
}

type packagesConfig struct {
	XMLName  xml.Name `xml:"packages"`
	Packages []struct {
		ID      string `xml:"id,attr"`
		Version string `xml:"version,attr"`
	} `xml:"package"`
}

// ScanPackagesConfig parses a legacy packages.config.
func (s *Scanner) ScanPackagesConfig(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var cfg packagesConfig
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse packages.config: %w", err)
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	for _, p := range cfg.Packages {
		if p.ID == "" {
			continue
		}
		key := strings.ToLower(p.ID) + "\x00" + p.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		confidence := "medium"
		if p.Version == "" {
			confidence = "low"
		}
		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = p.ID
		r.NormalizedName = strings.ToLower(p.ID)
		r.Version = p.Version
		r.ProjectPath = projectPath
		r.PackageManager = "nuget"
		r.SourceType = "nuget-packages-config"
		r.SourceFile = path
		r.Confidence = confidence
		s.Emit(r)
	}
	return nil
}

func (s *Scanner) readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
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
