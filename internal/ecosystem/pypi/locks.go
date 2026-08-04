package pypi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/normalize"
	"github.com/perplexityai/bumblebee/internal/toml"
)

// Python declaration and lock files.
//
// The dist-info/egg-info scanners in pypi.go read *installed* state. These
// read *declared* state, which is what npm/pnpm/yarn coverage has always
// done for JavaScript. Closing that asymmetry means a project whose
// dependencies are pinned but not currently installed in a local
// environment is still visible during an exposure sweep.
//
// Confidence follows how much the file proves:
//
//   - Pipfile.lock, poetry.lock, uv.lock, pylock.toml are resolved locks
//     with exact versions: high.
//   - A requirements.txt "==" pin is an exact version, but the file is a
//     request rather than a record of an install: medium.
//   - A requirements.txt entry with any other specifier has no single
//     version. It is recorded at low confidence with the raw specifier in
//     requested_spec and no version, matching how MCP server references
//     are handled.

func IsRequirementsTxt(base string) bool {
	// requirements.txt is conventionally suffixed for split environments
	// (requirements-dev.txt, requirements_test.txt).
	if base == "requirements.txt" {
		return true
	}
	if !strings.HasSuffix(base, ".txt") {
		return false
	}
	stem := strings.TrimSuffix(base, ".txt")
	return strings.HasPrefix(stem, "requirements-") || strings.HasPrefix(stem, "requirements_")
}

func IsPipfileLock(base string) bool { return base == "Pipfile.lock" }
func IsPoetryLock(base string) bool  { return base == "poetry.lock" }
func IsUvLock(base string) bool      { return base == "uv.lock" }
func IsPylockTOML(base string) bool  { return base == "pylock.toml" }

// --- requirements.txt -----------------------------------------------------

func (s *Scanner) ScanRequirementsTxt(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var pending strings.Builder
	emitLine := func(line string) {
		name, version, spec, ok := parseRequirement(line)
		if !ok {
			return
		}
		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = name
		r.NormalizedName = normalize.PyPI(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "pip"
		r.SourceType = "pip-requirements"
		r.SourceFile = path
		direct := true
		r.DirectDependency = &direct
		if version != "" {
			r.Confidence = "medium"
		} else {
			r.RequestedSpec = spec
			r.Confidence = "low"
		}
		s.Emit(r)
	}

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		// A trailing backslash continues onto the next line; hash-pinned
		// requirements use this heavily.
		if strings.HasSuffix(line, "\\") {
			pending.WriteString(strings.TrimSuffix(line, "\\"))
			continue
		}
		if pending.Len() > 0 {
			pending.WriteString(line)
			line = pending.String()
			pending.Reset()
		}
		emitLine(line)
	}
	if pending.Len() > 0 {
		emitLine(pending.String())
	}
	return nil
}

// parseRequirement extracts the package name and, when the specifier is an
// exact "==" pin, its version. Options (-r, -e, --index-url), environment
// markers, extras, and inline hashes are stripped.
func parseRequirement(line string) (name, version, spec string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", "", false
	}
	// Option lines and editable/VCS installs do not name a registry
	// release we can pin.
	if strings.HasPrefix(line, "-") {
		return "", "", "", false
	}
	if i := strings.Index(line, " #"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	// Drop environment markers and inline hashes.
	if i := strings.Index(line, ";"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if i := strings.Index(line, "--hash"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if line == "" {
		return "", "", "", false
	}
	// A bare URL or path requirement carries no usable name.
	if strings.Contains(line, "://") || strings.HasPrefix(line, ".") {
		return "", "", "", false
	}
	spec = line
	// Split the name off the first specifier character.
	idx := strings.IndexAny(line, "=<>!~[ ")
	if idx < 0 {
		return line, "", spec, true
	}
	name = strings.TrimSpace(line[:idx])
	if name == "" {
		return "", "", "", false
	}
	rest := strings.TrimSpace(line[idx:])
	// Extras: name[extra]==1.2.3
	if strings.HasPrefix(rest, "[") {
		if close := strings.Index(rest, "]"); close >= 0 {
			rest = strings.TrimSpace(rest[close+1:])
		}
	}
	if strings.HasPrefix(rest, "==") {
		v := strings.TrimSpace(strings.TrimPrefix(rest, "=="))
		// A wildcard pin ("==1.2.*") is not an exact version.
		if v != "" && !strings.ContainsAny(v, "*, ") {
			return name, v, spec, true
		}
	}
	return name, "", spec, true
}

// --- Pipfile.lock ---------------------------------------------------------

type pipfileLock struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	Version string `json:"version"`
}

func (s *Scanner) ScanPipfileLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var lock pipfileLock
	if err := json.Unmarshal(data, &lock); err != nil {
		s.note(path, "unparseable Pipfile.lock: "+err.Error())
		return nil
	}
	projectPath := filepath.Dir(path)
	emitGroup := func(entries map[string]pipfileEntry, scope string) {
		for name, entry := range entries {
			// Pipenv writes versions as "==1.2.3".
			version := strings.TrimPrefix(strings.TrimSpace(entry.Version), "==")
			if name == "" || version == "" {
				continue
			}
			r := base
			r.Ecosystem = Ecosystem
			r.PackageName = name
			r.NormalizedName = normalize.PyPI(name)
			r.Version = version
			r.ProjectPath = projectPath
			r.PackageManager = "pipenv"
			r.SourceType = "pipenv-lock"
			r.SourceFile = path
			r.InstallScope = scope
			r.Confidence = "high"
			s.Emit(r)
		}
	}
	emitGroup(lock.Default, "")
	emitGroup(lock.Develop, "dev")
	return nil
}

// --- poetry.lock / uv.lock / pylock.toml ----------------------------------

func (s *Scanner) ScanPoetryLock(path string, base model.Record) error {
	return s.scanTOMLLock(path, base, "package", "poetry", "poetry-lock")
}

func (s *Scanner) ScanUvLock(path string, base model.Record) error {
	return s.scanTOMLLock(path, base, "package", "uv", "uv-lock")
}

// ScanPylockTOML reads the PEP 751 lock format, which names its array of
// tables "packages" rather than "package".
func (s *Scanner) ScanPylockTOML(path string, base model.Record) error {
	return s.scanTOMLLock(path, base, "packages", "pylock", "pylock")
}

func (s *Scanner) scanTOMLLock(path string, base model.Record, arrayKey, manager, sourceType string) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	root, err := toml.Parse(data)
	if err != nil {
		s.note(path, "unparseable "+filepath.Base(path)+": "+err.Error())
		return nil
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})
	for _, pkg := range toml.Tables(root[arrayKey]) {
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
		r.NormalizedName = normalize.PyPI(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = manager
		r.SourceType = sourceType
		r.SourceFile = path
		// Poetry marks dev/optional packages with a category or optional
		// flag depending on lock generation.
		if category, _ := toml.String(pkg["category"]); category != "" && category != "main" {
			r.InstallScope = category
		}
		if optional, ok := pkg["optional"].(bool); ok && optional {
			r.InstallScope = "optional"
		}
		r.Confidence = "high"
		s.Emit(r)
	}
	return nil
}

func (s *Scanner) note(path, msg string) {
	if s.Diag != nil {
		s.Diag("warn", path, msg)
	}
}
