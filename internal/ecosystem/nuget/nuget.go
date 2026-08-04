// Package nuget scans .NET / NuGet dependency artifacts.
//
// Four file shapes are recognised, in descending order of how much they
// prove about what is actually installed:
//
//   - packages.lock.json — the NuGet lock file. Resolved, exact versions
//     for direct and transitive dependencies. High confidence.
//   - *.deps.json — the .NET Core runtime dependency manifest emitted next
//     to a built assembly. Names and versions are exact and the file only
//     exists after a build, so it reflects a real resolved graph.
//   - packages.config — the legacy (pre-PackageReference) format. Exact
//     versions, but direct dependencies only.
//   - Directory.Packages.props / Packages.props — central package version
//     management. These are declarations rather than a resolved graph:
//     a version here is what the build was asked for, not necessarily
//     what it restored, so records are emitted at medium confidence.
//
// No `dotnet` or `nuget` commands are executed; every record comes from
// reading one of the files above.
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

// IsDepsJSON matches the `<assembly>.deps.json` manifest emitted by the
// .NET Core build. `packages.lock.json` also ends in ".json" but is
// matched by its own predicate first; the explicit exclusion here keeps
// the two from overlapping if the dispatch order ever changes.
func IsDepsJSON(base string) bool {
	return strings.HasSuffix(base, ".deps.json") && base != "packages.lock.json"
}

// IsPackagesProps matches central package management files. Both the
// modern `Directory.Packages.props` and the legacy `Packages.props`
// spelling are supported.
func IsPackagesProps(base string) bool {
	return base == "Directory.Packages.props" || base == "Packages.props"
}

// packagesLockFile mirrors the packages.lock.json schema. Dependencies are
// keyed by target framework, then by package id.
type packagesLockFile struct {
	Version      int                                   `json:"version"`
	Dependencies map[string]map[string]packagesLockDep `json:"dependencies"`
}

type packagesLockDep struct {
	Type     string `json:"type"`
	Resolved string `json:"resolved"`
}

func (s *Scanner) ScanPackagesLockJSON(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var lock packagesLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		s.note(path, "unparseable packages.lock.json: "+err.Error())
		return nil
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})
	for _, byPackage := range lock.Dependencies {
		for name, dep := range byPackage {
			if name == "" || dep.Resolved == "" {
				continue
			}
			key := name + "\x00" + dep.Resolved
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}

			r := base
			r.Ecosystem = Ecosystem
			r.PackageName = name
			r.NormalizedName = normalizeName(name)
			r.Version = dep.Resolved
			r.ProjectPath = projectPath
			r.PackageManager = "nuget"
			r.SourceType = "nuget-packages-lock"
			r.SourceFile = path
			// "Direct" is NuGet's own term for a top-level PackageReference;
			// "Transitive" and "Project" are the other values it emits.
			switch dep.Type {
			case "Direct":
				direct := true
				r.DirectDependency = &direct
			case "Transitive":
				direct := false
				r.DirectDependency = &direct
				r.InstallScope = "indirect"
			}
			r.Confidence = "high"
			s.Emit(r)
		}
	}
	return nil
}

// depsFile mirrors the parts of *.deps.json we need. The "libraries" map is
// keyed by "<name>/<version>" and carries the package type.
type depsFile struct {
	Libraries map[string]struct {
		Type string `json:"type"`
	} `json:"libraries"`
}

func (s *Scanner) ScanDepsJSON(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var deps depsFile
	if err := json.Unmarshal(data, &deps); err != nil {
		s.note(path, "unparseable deps.json: "+err.Error())
		return nil
	}
	if len(deps.Libraries) == 0 {
		return nil
	}
	projectPath := filepath.Dir(path)
	for key, lib := range deps.Libraries {
		// Project references are the assembly being built, not a package.
		if strings.EqualFold(lib.Type, "project") {
			continue
		}
		name, version, ok := strings.Cut(key, "/")
		if !ok || name == "" || version == "" {
			continue
		}
		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = name
		r.NormalizedName = normalizeName(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "nuget"
		r.SourceType = "nuget-deps-json"
		r.SourceFile = path
		r.Confidence = "high"
		s.Emit(r)
	}
	return nil
}

// packagesConfig mirrors the legacy packages.config XML shape.
type packagesConfig struct {
	XMLName  xml.Name `xml:"packages"`
	Packages []struct {
		ID      string `xml:"id,attr"`
		Version string `xml:"version,attr"`
	} `xml:"package"`
}

func (s *Scanner) ScanPackagesConfig(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var cfg packagesConfig
	if err := xml.Unmarshal(data, &cfg); err != nil {
		s.note(path, "unparseable packages.config: "+err.Error())
		return nil
	}
	projectPath := filepath.Dir(path)
	for _, pkg := range cfg.Packages {
		if pkg.ID == "" || pkg.Version == "" {
			continue
		}
		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = pkg.ID
		r.NormalizedName = normalizeName(pkg.ID)
		r.Version = pkg.Version
		r.ProjectPath = projectPath
		r.PackageManager = "nuget"
		r.SourceType = "nuget-packages-config"
		r.SourceFile = path
		// packages.config lists only what the project asked for directly.
		direct := true
		r.DirectDependency = &direct
		r.Confidence = "high"
		s.Emit(r)
	}
	return nil
}

// packagesProps mirrors the MSBuild props shape used by central package
// management. Only PackageVersion entries carry a pinned version;
// PackageReference entries in these files usually omit it.
type packagesProps struct {
	XMLName    xml.Name `xml:"Project"`
	ItemGroups []struct {
		PackageVersions []struct {
			Include string `xml:"Include,attr"`
			Version string `xml:"Version,attr"`
		} `xml:"PackageVersion"`
	} `xml:"ItemGroup"`
}

func (s *Scanner) ScanPackagesProps(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var props packagesProps
	if err := xml.Unmarshal(data, &props); err != nil {
		s.note(path, "unparseable Packages.props: "+err.Error())
		return nil
	}
	projectPath := filepath.Dir(path)
	for _, group := range props.ItemGroups {
		for _, pv := range group.PackageVersions {
			if pv.Include == "" || pv.Version == "" {
				continue
			}
			// MSBuild property references ($(Foo)) and version ranges are
			// not resolved without running the build, so they are not a
			// usable exact version.
			if strings.ContainsAny(pv.Version, "$[](),*") {
				continue
			}
			r := base
			r.Ecosystem = Ecosystem
			r.PackageName = pv.Include
			r.NormalizedName = normalizeName(pv.Include)
			r.Version = pv.Version
			r.ProjectPath = projectPath
			r.PackageManager = "nuget"
			r.SourceType = "nuget-packages-props"
			r.SourceFile = path
			// A declared central version is what the build asks for, not
			// proof of what was restored.
			r.Confidence = "medium"
			s.Emit(r)
		}
	}
	return nil
}

// IsNuspec matches the manifest NuGet writes into the global packages
// folder. Unlike the four project-side files above, a `.nuspec` in the
// cache is evidence of what is actually installed on the machine — the
// same role `*.gemspec` plays for RubyGems.
func IsNuspec(base string) bool { return strings.HasSuffix(base, ".nuspec") }

// IsCachedNuspec reports whether path sits in the per-version layout the
// global packages folder uses:
//
//	<cache>/<id>/<version>/<id>.nuspec
//
// A `.nuspec` inside a source tree is an authoring template whose
// <version> is often a placeholder, so the directory shape is required
// rather than accepting the basename anywhere.
func IsCachedNuspec(path string) bool {
	base := filepath.Base(path)
	if !IsNuspec(base) {
		return false
	}
	versionDir := filepath.Dir(path)
	idDir := filepath.Dir(versionDir)
	if idDir == versionDir {
		return false
	}
	// The file stem must match the package-id directory, case-insensitively.
	stem := strings.TrimSuffix(base, ".nuspec")
	return strings.EqualFold(stem, filepath.Base(idDir))
}

type nuspec struct {
	XMLName  xml.Name `xml:"package"`
	Metadata struct {
		ID      string `xml:"id"`
		Version string `xml:"version"`
	} `xml:"metadata"`
}

func (s *Scanner) ScanNuspec(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var spec nuspec
	if err := xml.Unmarshal(data, &spec); err != nil {
		s.note(path, "unparseable nuspec: "+err.Error())
		return nil
	}
	id := strings.TrimSpace(spec.Metadata.ID)
	version := strings.TrimSpace(spec.Metadata.Version)
	if id == "" || version == "" {
		return nil
	}
	// An authoring template can carry a substituted token such as
	// "$version$"; that is not an installed version.
	if strings.Contains(version, "$") {
		return nil
	}
	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = id
	r.NormalizedName = normalizeName(id)
	r.Version = version
	r.ProjectPath = filepath.Dir(path)
	r.PackageManager = "nuget"
	r.SourceType = "nuget-nuspec"
	r.SourceFile = path
	r.InstallScope = "global"
	r.Confidence = "high"
	s.Emit(r)
	return nil
}

// normalizeName lowercases the package id. NuGet ids are case-insensitive
// and the gallery treats differing cases as the same package.
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
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
