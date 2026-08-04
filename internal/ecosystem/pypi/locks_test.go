package pypi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func scanLock(t *testing.T, name, content string, fn func(*Scanner, string, model.Record) error) []model.Record {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { got = append(got, r) },
		Diag:        func(level, path, msg string) {},
	}
	if err := fn(s, path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestIsRequirementsTxt(t *testing.T) {
	for _, ok := range []string{"requirements.txt", "requirements-dev.txt", "requirements_test.txt"} {
		if !IsRequirementsTxt(ok) {
			t.Errorf("IsRequirementsTxt(%q) = false", ok)
		}
	}
	for _, no := range []string{"notes.txt", "README.txt", "requirements.md"} {
		if IsRequirementsTxt(no) {
			t.Errorf("IsRequirementsTxt(%q) = true", no)
		}
	}
}

func TestScanRequirementsTxt(t *testing.T) {
	got := scanLock(t, "requirements.txt", `# comment
requests==2.31.0
flask>=2.0
django[argon2]==5.0.1
-r other.txt
-e .
https://example.com/pkg.tar.gz
urllib3==2.1.0 ; python_version >= "3.8"
pinned-wild==1.2.*
`, (*Scanner).ScanRequirementsTxt)

	byName := map[string]model.Record{}
	for _, r := range got {
		byName[r.PackageName] = r
	}
	// Options, editable installs, and bare URLs carry no package identity.
	for _, absent := range []string{"-r", "-e", "https"} {
		if _, ok := byName[absent]; ok {
			t.Errorf("%q should not be recorded", absent)
		}
	}

	req, ok := byName["requests"]
	if !ok {
		t.Fatal("requests missing")
	}
	if req.Version != "2.31.0" {
		t.Errorf("requests version = %q", req.Version)
	}
	// A pin is exact, but the file is a request rather than an install.
	if req.Confidence != "medium" {
		t.Errorf("pinned requirement confidence = %q, want medium", req.Confidence)
	}
	if req.DirectDependency == nil || !*req.DirectDependency {
		t.Error("requirements entries are direct")
	}

	// Extras must be stripped from the name but keep the pin.
	dj, ok := byName["django"]
	if !ok {
		t.Fatalf("django missing (extras not stripped?): %+v", got)
	}
	if dj.Version != "5.0.1" {
		t.Errorf("django version = %q", dj.Version)
	}

	// Environment markers must not defeat the pin.
	if u := byName["urllib3"]; u.Version != "2.1.0" {
		t.Errorf("urllib3 version = %q, want marker stripped", u.Version)
	}

	// A range has no single version; the spec is preserved instead.
	fl, ok := byName["flask"]
	if !ok {
		t.Fatal("flask missing")
	}
	if fl.Version != "" || fl.Confidence != "low" {
		t.Errorf("flask version/confidence = %q/%q, want empty/low", fl.Version, fl.Confidence)
	}
	if fl.RequestedSpec == "" {
		t.Error("unpinned requirement should record its spec")
	}

	// A wildcard pin is not an exact version.
	if w := byName["pinned-wild"]; w.Version != "" {
		t.Errorf("wildcard pin version = %q, want empty", w.Version)
	}
}

func TestScanRequirementsTxtLineContinuation(t *testing.T) {
	got := scanLock(t, "requirements.txt", `requests==2.31.0 \
    --hash=sha256:abc \
    --hash=sha256:def
`, (*Scanner).ScanRequirementsTxt)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(got), got)
	}
	if got[0].PackageName != "requests" || got[0].Version != "2.31.0" {
		t.Errorf("record = %q@%q", got[0].PackageName, got[0].Version)
	}
}

func TestScanPipfileLock(t *testing.T) {
	got := scanLock(t, "Pipfile.lock", `{
  "default": { "requests": { "version": "==2.31.0" } },
  "develop": { "pytest":   { "version": "==7.4.3" } }
}`, (*Scanner).ScanPipfileLock)

	byName := map[string]model.Record{}
	for _, r := range got {
		byName[r.PackageName] = r
	}
	if len(byName) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(byName), got)
	}
	if r := byName["requests"]; r.Version != "2.31.0" || r.Confidence != "high" {
		t.Errorf("requests = %q/%q, want the '==' prefix stripped", r.Version, r.Confidence)
	}
	if r := byName["pytest"]; r.InstallScope != "dev" {
		t.Errorf("develop scope = %q", r.InstallScope)
	}
}

func TestScanPoetryLock(t *testing.T) {
	got := scanLock(t, "poetry.lock", `[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
category = "main"
optional = false

[[package]]
name = "pytest"
version = "7.4.3"
category = "dev"
optional = false
`, (*Scanner).ScanPoetryLock)

	byName := map[string]model.Record{}
	for _, r := range got {
		byName[r.PackageName] = r
	}
	if len(byName) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(byName), got)
	}
	if r := byName["requests"]; r.Version != "2.31.0" || r.Confidence != "high" {
		t.Errorf("requests = %q/%q", r.Version, r.Confidence)
	}
	if r := byName["pytest"]; r.InstallScope != "dev" {
		t.Errorf("dev category scope = %q", r.InstallScope)
	}
}

func TestScanUvLockAndPylock(t *testing.T) {
	uv := scanLock(t, "uv.lock", `version = 1

[[package]]
name = "click"
version = "8.1.7"
source = { registry = "https://pypi.org/simple" }
`, (*Scanner).ScanUvLock)
	if len(uv) != 1 || uv[0].PackageName != "click" || uv[0].SourceType != "uv-lock" {
		t.Fatalf("uv.lock records = %+v", uv)
	}

	// PEP 751 names its array "packages" rather than "package".
	pylock := scanLock(t, "pylock.toml", `lock-version = "1.0"

[[packages]]
name = "attrs"
version = "23.2.0"
`, (*Scanner).ScanPylockTOML)
	if len(pylock) != 1 || pylock[0].PackageName != "attrs" || pylock[0].SourceType != "pylock" {
		t.Fatalf("pylock.toml records = %+v", pylock)
	}
}

func TestLockNamesAreNormalizedPEP503(t *testing.T) {
	got := scanLock(t, "poetry.lock", `[[package]]
name = "Zope.Interface_Thing"
version = "1.0.0"
`, (*Scanner).ScanPoetryLock)
	if len(got) != 1 {
		t.Fatal("expected one record")
	}
	if got[0].NormalizedName != "zope-interface-thing" {
		t.Errorf("normalized = %q, want PEP 503 form", got[0].NormalizedName)
	}
}
