package nuget

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func newScanner(t *testing.T) (*Scanner, *[]model.Record) {
	t.Helper()
	var got []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { got = append(got, r) },
		Diag:        func(level, path, msg string) {},
	}
	return s, &got
}

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPredicates(t *testing.T) {
	if !IsPackagesLockJSON("packages.lock.json") || IsPackagesLockJSON("packages.json") {
		t.Error("IsPackagesLockJSON")
	}
	if !IsPackagesConfig("packages.config") {
		t.Error("IsPackagesConfig")
	}
	if !IsDepsJSON("MyApp.deps.json") {
		t.Error("IsDepsJSON should match assembly manifests")
	}
	// packages.lock.json must not fall through to the deps.json parser.
	if IsDepsJSON("packages.lock.json") {
		t.Error("IsDepsJSON must not match packages.lock.json")
	}
	if !IsPackagesProps("Directory.Packages.props") || !IsPackagesProps("Packages.props") {
		t.Error("IsPackagesProps should accept both spellings")
	}
	if IsPackagesProps("Other.props") {
		t.Error("IsPackagesProps matched an unrelated props file")
	}
}

func TestScanPackagesLockJSON(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "packages.lock.json", `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.3" },
      "System.Buffers":  { "type": "Transitive", "resolved": "4.5.1" }
    }
  }
}`)
	s, got := newScanner(t)
	if err := s.ScanPackagesLockJSON(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(*got), *got)
	}
	byName := map[string]model.Record{}
	for _, r := range *got {
		byName[r.PackageName] = r
	}
	nj, ok := byName["Newtonsoft.Json"]
	if !ok {
		t.Fatal("Newtonsoft.Json missing")
	}
	if nj.Version != "13.0.3" {
		t.Errorf("version = %q", nj.Version)
	}
	if nj.NormalizedName != "newtonsoft.json" {
		t.Errorf("normalized = %q, want lowercased", nj.NormalizedName)
	}
	if nj.Ecosystem != model.EcosystemNuGet {
		t.Errorf("ecosystem = %q", nj.Ecosystem)
	}
	if nj.DirectDependency == nil || !*nj.DirectDependency {
		t.Error("Direct dependency should be flagged direct")
	}
	if nj.Confidence != "high" {
		t.Errorf("confidence = %q, want high", nj.Confidence)
	}
	sb := byName["System.Buffers"]
	if sb.DirectDependency == nil || *sb.DirectDependency {
		t.Error("Transitive dependency should be flagged indirect")
	}
	if sb.InstallScope != "indirect" {
		t.Errorf("install scope = %q", sb.InstallScope)
	}
}

func TestScanDepsJSONSkipsProjectEntries(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "MyApp.deps.json", `{
  "libraries": {
    "MyApp/1.0.0": { "type": "project" },
    "Serilog/3.1.1": { "type": "package" }
  }
}`)
	s, got := newScanner(t)
	if err := s.ScanDepsJSON(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("got %d records, want 1 (project entry must be skipped): %+v", len(*got), *got)
	}
	r := (*got)[0]
	if r.PackageName != "Serilog" || r.Version != "3.1.1" {
		t.Errorf("record = %q@%q", r.PackageName, r.Version)
	}
	if r.SourceType != "nuget-deps-json" {
		t.Errorf("source type = %q", r.SourceType)
	}
}

func TestScanPackagesConfig(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "packages.config", `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="EntityFramework" version="6.4.4" targetFramework="net48" />
  <package id="jQuery" version="3.6.0" targetFramework="net48" />
</packages>`)
	s, got := newScanner(t)
	if err := s.ScanPackagesConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 2 {
		t.Fatalf("got %d records, want 2", len(*got))
	}
	for _, r := range *got {
		if r.DirectDependency == nil || !*r.DirectDependency {
			t.Errorf("%s should be direct", r.PackageName)
		}
		if r.Version == "" {
			t.Errorf("%s has no version", r.PackageName)
		}
	}
}

func TestScanPackagesPropsSkipsUnresolvedVersions(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "Directory.Packages.props", `<Project>
  <ItemGroup>
    <PackageVersion Include="Serilog" Version="3.1.1" />
    <PackageVersion Include="Polly" Version="$(PollyVersion)" />
    <PackageVersion Include="Ranged" Version="[1.0,2.0)" />
  </ItemGroup>
</Project>`)
	s, got := newScanner(t)
	if err := s.ScanPackagesProps(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("got %d records, want 1 (property and range must be skipped): %+v", len(*got), *got)
	}
	r := (*got)[0]
	if r.PackageName != "Serilog" {
		t.Errorf("package = %q", r.PackageName)
	}
	// A declared central version is not proof of what was restored.
	if r.Confidence != "medium" {
		t.Errorf("confidence = %q, want medium", r.Confidence)
	}
}

func TestMalformedInputIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	s, got := newScanner(t)
	cases := map[string]func(string, model.Record) error{
		"packages.lock.json":       s.ScanPackagesLockJSON,
		"packages.config":          s.ScanPackagesConfig,
		"Directory.Packages.props": s.ScanPackagesProps,
		"X.deps.json":              s.ScanDepsJSON,
	}
	for name, scan := range cases {
		path := write(t, dir, name, "{{{not valid")
		if err := scan(path, model.Record{}); err != nil {
			t.Errorf("%s: unparseable input should warn, not error: %v", name, err)
		}
	}
	if len(*got) != 0 {
		t.Errorf("malformed input emitted %d records", len(*got))
	}
}

func TestIsCachedNuspecRequiresGlobalCacheLayout(t *testing.T) {
	// <cache>/<id>/<version>/<id>.nuspec — the global packages folder.
	if !IsCachedNuspec(filepath.Join("pkgs", "serilog", "3.1.1", "serilog.nuspec")) {
		t.Error("global-cache layout should match")
	}
	// NuGet lowercases cache directories; ids are case-insensitive.
	if !IsCachedNuspec(filepath.Join("pkgs", "Serilog", "3.1.1", "serilog.nuspec")) {
		t.Error("id comparison should be case-insensitive")
	}
	// An authoring template in a source tree must not match.
	if IsCachedNuspec(filepath.Join("src", "MyProject", "MyProject.nuspec")) {
		t.Error("source-tree nuspec must not match: the stem does not match its parent dir")
	}
	if IsCachedNuspec(filepath.Join("pkgs", "serilog", "3.1.1", "other.nuspec")) {
		t.Error("stem/id mismatch must not match")
	}
}

func TestScanNuspec(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "serilog.nuspec", `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Serilog</id>
    <version>3.1.1</version>
    <authors>Serilog Contributors</authors>
  </metadata>
</package>`)
	s, got := newScanner(t)
	if err := s.ScanNuspec(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(*got), *got)
	}
	r := (*got)[0]
	if r.PackageName != "Serilog" || r.Version != "3.1.1" {
		t.Errorf("record = %q@%q", r.PackageName, r.Version)
	}
	if r.NormalizedName != "serilog" {
		t.Errorf("normalized = %q", r.NormalizedName)
	}
	if r.SourceType != "nuget-nuspec" || r.InstallScope != "global" {
		t.Errorf("source/scope = %q/%q", r.SourceType, r.InstallScope)
	}
	if r.Confidence != "high" {
		t.Errorf("confidence = %q", r.Confidence)
	}
}

// An authoring nuspec often carries replacement tokens; "$version$" is
// not an installed version.
func TestScanNuspecSkipsSubstitutionTokens(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "tmpl.nuspec",
		`<package><metadata><id>Thing</id><version>$version$</version></metadata></package>`)
	s, got := newScanner(t)
	if err := s.ScanNuspec(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 0 {
		t.Errorf("token version should not be emitted, got %+v", *got)
	}
}
