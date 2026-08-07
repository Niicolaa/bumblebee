// Package pylock scans Python dependency lock and requirement files.
//
// It is the declared-state counterpart to package pypi, which reads
// installed metadata (*.dist-info). Both emit ecosystem "pypi". The
// split matters for confidence: a dist-info directory proves a package
// is installed at a version, while a lockfile records what a project
// resolved to and may or may not have installed into this tree.
//
// Formats read:
//
//	requirements.txt   line-based, PEP 508
//	Pipfile.lock       JSON
//	poetry.lock        TOML, [[package]] tables
//	uv.lock            TOML, [[package]] tables
//	pylock.toml        TOML, [[packages]] tables (PEP 751)
//
// No resolver is run and no index is contacted; only what the file
// itself states is emitted.
package pylock

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/ecosystem/safeopen"
	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/normalize"
	"github.com/perplexityai/bumblebee/internal/toml"
)

const Ecosystem = model.EcosystemPyPI

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsRequirementsTxt(base string) bool {
	// requirements.txt plus the common requirements-dev.txt / requirements_test.txt
	// variants, and dev-requirements.txt.
	if !strings.HasSuffix(base, ".txt") {
		return false
	}
	stem := strings.TrimSuffix(base, ".txt")
	return stem == "requirements" ||
		strings.HasPrefix(stem, "requirements-") ||
		strings.HasPrefix(stem, "requirements_") ||
		strings.HasSuffix(stem, "-requirements") ||
		strings.HasSuffix(stem, "_requirements")
}

func IsPipfileLock(base string) bool { return base == "Pipfile.lock" }
func IsPoetryLock(base string) bool  { return base == "poetry.lock" }
func IsUVLock(base string) bool      { return base == "uv.lock" }
func IsPylockTOML(base string) bool  { return base == "pylock.toml" }

// ScanRequirementsTxt parses a requirements file.
//
// Only `name==version` pins yield a version. Every other specifier
// (`>=`, `~=`, unpinned, URL, VCS, editable) names a real dependency but
// does not tell us which version is present, so the record carries the
// name with an empty version at low confidence. That distinction is the
// whole point: `requests>=2.0` on disk is not evidence that the
// compromised 2.32.4 is installed, and emitting it as though it were
// would manufacture false positives across a fleet.
func (s *Scanner) ScanRequirementsTxt(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(stripHashComment(sc.Text()))
		if line == "" {
			continue
		}
		// Options (-r other.txt, --index-url, -e .) are not requirements.
		if strings.HasPrefix(line, "-") {
			continue
		}
		name, version, confidence := parseRequirement(line)
		if name == "" {
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
		r.NormalizedName = normalize.PyPI(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "pip"
		r.SourceType = "pypi-requirements-txt"
		r.SourceFile = path
		r.Confidence = confidence
		s.Emit(r)
	}
	return sc.Err()
}

// parseRequirement pulls the project name and, when the specifier is an
// exact pin, the version out of one PEP 508 requirement line.
func parseRequirement(line string) (name, version, confidence string) {
	// Strip environment markers ("; python_version < '3.10'").
	if i := strings.Index(line, ";"); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", ""
	}
	// URL and VCS requirements ("pkg @ https://...", "git+https://...")
	// name a package but pin no registry version we can match on.
	if i := strings.Index(line, "@"); i >= 0 {
		nm := strings.TrimSpace(line[:i])
		if nm == "" || strings.Contains(nm, ":") {
			return "", "", ""
		}
		return stripExtras(nm), "", "low"
	}
	if strings.Contains(line, "://") {
		return "", "", ""
	}

	if i := strings.Index(line, "=="); i >= 0 {
		nm := stripExtras(strings.TrimSpace(line[:i]))
		ver := strings.TrimSpace(line[i+2:])
		// "==1.2.*" is a range, not a pin.
		if nm == "" || ver == "" || strings.ContainsAny(ver, "*,") {
			return nm, "", "low"
		}
		return nm, ver, "medium"
	}
	// Any other specifier: name only.
	if i := strings.IndexAny(line, "<>=!~"); i >= 0 {
		return stripExtras(strings.TrimSpace(line[:i])), "", "low"
	}
	return stripExtras(line), "", "low"
}

// stripExtras removes a PEP 508 extras suffix: "requests[security]".
func stripExtras(name string) string {
	if i := strings.Index(name, "["); i >= 0 {
		name = name[:i]
	}
	return strings.TrimSpace(name)
}

func stripHashComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

type pipfileLock struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	Version string `json:"version"`
}

// ScanPipfileLock parses a Pipfile.lock. Versions are stored with their
// operator ("==2.32.3"), and pipenv only ever writes exact pins there.
func (s *Scanner) ScanPipfileLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var lock pipfileLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("parse Pipfile.lock: %w", err)
	}
	projectPath := filepath.Dir(path)

	for _, group := range []struct {
		scope   string
		entries map[string]pipfileEntry
	}{
		{"prod", lock.Default},
		{"dev", lock.Develop},
	} {
		for name, e := range group.entries {
			version := strings.TrimPrefix(strings.TrimSpace(e.Version), "==")
			confidence := "medium"
			if version == "" {
				confidence = "low"
			}
			r := base
			r.Ecosystem = Ecosystem
			r.PackageName = name
			r.NormalizedName = normalize.PyPI(name)
			r.Version = version
			r.ProjectPath = projectPath
			r.InstallScope = group.scope
			r.PackageManager = "pipenv"
			r.SourceType = "pypi-pipfile-lock"
			r.SourceFile = path
			r.Confidence = confidence
			s.Emit(r)
		}
	}
	return nil
}

// ScanPoetryLock parses a poetry.lock ([[package]] tables).
func (s *Scanner) ScanPoetryLock(path string, base model.Record) error {
	return s.scanTOMLLock(path, base, "package", "poetry", "pypi-poetry-lock")
}

// ScanUVLock parses a uv.lock ([[package]] tables).
func (s *Scanner) ScanUVLock(path string, base model.Record) error {
	return s.scanTOMLLock(path, base, "package", "uv", "pypi-uv-lock")
}

// ScanPylockTOML parses a PEP 751 pylock.toml ([[packages]] tables).
func (s *Scanner) ScanPylockTOML(path string, base model.Record) error {
	return s.scanTOMLLock(path, base, "packages", "pip", "pypi-pylock-toml")
}

// scanTOMLLock is the shared body for the three TOML lock formats: they
// differ only in the table name they use and the manager that wrote them.
func (s *Scanner) scanTOMLLock(path string, base model.Record, tableName, manager, sourceType string) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	doc, err := toml.Parse(data)
	if err != nil {
		// Structural damage: report the file as unparsed rather than
		// emitting whatever happened to parse before the bad line.
		return fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	for _, tbl := range doc.TablesNamed(tableName) {
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

		// A lock entry pointing at a local directory or VCS checkout has
		// no registry version to match a catalog against.
		confidence := "medium"
		if version == "" {
			confidence = "low"
		}
		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = name
		r.NormalizedName = normalize.PyPI(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = manager
		r.SourceType = sourceType
		r.SourceFile = path
		r.Confidence = confidence
		s.Emit(r)
	}
	return nil
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
			s.Diag("warn", path, "file exceeds max-file-size; parsed prefix only")
		}
		return nil, errors.New("file exceeds max-file-size")
	}
	return data, nil
}
