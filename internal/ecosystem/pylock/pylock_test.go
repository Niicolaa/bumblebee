package pylock

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func scanOne(t *testing.T, name, body string, fn func(*Scanner, string, model.Record) error) []model.Record {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := fn(s, path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	return out
}

// Only `==` pins carry a version. Anything looser names the package but
// must not claim a version, or a fleet scan invents false positives.
func TestScanRequirementsTxt(t *testing.T) {
	body := `# comment
requests==2.32.3
flask >= 2.0
django~=4.2
urllib3==2.*
numpy
requests[security]==2.32.3
pkg @ https://example.com/pkg.whl
-r other-requirements.txt
--index-url https://example.com/simple
click==8.1.7 ; python_version < "3.12"
`
	out := scanOne(t, "requirements.txt", body, (*Scanner).ScanRequirementsTxt)

	want := map[string]struct {
		version    string
		confidence string
	}{
		"click":    {"8.1.7", "medium"},
		"django":   {"", "low"},
		"flask":    {"", "low"},
		"numpy":    {"", "low"},
		"pkg":      {"", "low"},
		"requests": {"2.32.3", "medium"},
		"urllib3":  {"", "low"},
	}
	if len(out) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(out), len(want), names(out))
	}
	for _, r := range out {
		w, ok := want[r.PackageName]
		if !ok {
			t.Errorf("unexpected package %q", r.PackageName)
			continue
		}
		if r.Version != w.version {
			t.Errorf("%s version=%q, want %q", r.PackageName, r.Version, w.version)
		}
		if r.Confidence != w.confidence {
			t.Errorf("%s confidence=%q, want %q", r.PackageName, r.Confidence, w.confidence)
		}
		if r.SourceType != "pypi-requirements-txt" {
			t.Errorf("%s source_type=%q", r.PackageName, r.SourceType)
		}
	}
}

func TestScanPipfileLock(t *testing.T) {
	body := `{
  "_meta": {"hash": {"sha256": "abc"}},
  "default": {
    "requests": {"version": "==2.32.3"},
    "certifi": {"version": "==2024.7.4"}
  },
  "develop": {
    "pytest": {"version": "==8.3.2"}
  }
}`
	out := scanOne(t, "Pipfile.lock", body, (*Scanner).ScanPipfileLock)
	if len(out) != 3 {
		t.Fatalf("got %d records: %+v", len(out), names(out))
	}
	byName := map[string]model.Record{}
	for _, r := range out {
		byName[r.PackageName] = r
	}
	if got := byName["requests"]; got.Version != "2.32.3" || got.InstallScope != "prod" {
		t.Errorf("requests=%+v", got)
	}
	if got := byName["pytest"]; got.Version != "8.3.2" || got.InstallScope != "dev" {
		t.Errorf("pytest=%+v", got)
	}
}

func TestScanPoetryLock(t *testing.T) {
	body := `[[package]]
name = "requests"
version = "2.32.3"
files = [
    {file = "requests-2.32.3-py3-none-any.whl", hash = "sha256:abc"},
]

[package.dependencies]
certifi = ">=2017.4.17"

[[package]]
name = "certifi"
version = "2024.7.4"
files = []
`
	out := scanOne(t, "poetry.lock", body, (*Scanner).ScanPoetryLock)
	if len(out) != 2 {
		t.Fatalf("got %d records: %+v", len(out), names(out))
	}
	if out[0].PackageName != "certifi" || out[0].Version != "2024.7.4" {
		t.Errorf("certifi=%+v", out[0])
	}
	if out[1].PackageName != "requests" || out[1].Version != "2.32.3" {
		t.Errorf("requests=%+v", out[1])
	}
	for _, r := range out {
		if r.SourceType != "pypi-poetry-lock" || r.PackageManager != "poetry" {
			t.Errorf("%+v", r)
		}
	}
}

func TestScanUVLock(t *testing.T) {
	body := `version = 1
requires-python = ">=3.11"

[[package]]
name = "anyio"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
]

[[package]]
name = "idna"
version = "3.7"
`
	out := scanOne(t, "uv.lock", body, (*Scanner).ScanUVLock)
	if len(out) != 2 {
		t.Fatalf("got %d records: %+v", len(out), names(out))
	}
	if out[0].PackageName != "anyio" || out[0].Version != "4.4.0" {
		t.Errorf("anyio=%+v", out[0])
	}
	if out[1].PackageName != "idna" || out[1].Version != "3.7" {
		t.Errorf("idna=%+v", out[1])
	}
}

// PEP 751 uses [[packages]], not [[package]].
func TestScanPylockTOML(t *testing.T) {
	body := `lock-version = "1.0"
created-by = "pip"

[[packages]]
name = "attrs"
version = "24.2.0"

[[packages]]
name = "sniffio"
version = "1.3.1"
`
	out := scanOne(t, "pylock.toml", body, (*Scanner).ScanPylockTOML)
	if len(out) != 2 {
		t.Fatalf("got %d records: %+v", len(out), names(out))
	}
	if out[0].PackageName != "attrs" || out[0].Version != "24.2.0" {
		t.Errorf("attrs=%+v", out[0])
	}
}

// A structurally broken lockfile must error, not emit a partial list
// that a receiver would treat as the machine's full inventory.
func TestScanPoetryLockStructuralErrorIsFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "poetry.lock")
	body := "[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\n\n[[package\nname = \"broken\"\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanPoetryLock(path, model.Record{}); err == nil {
		t.Fatal("want error for malformed lockfile, got nil")
	}
	if len(out) != 0 {
		t.Errorf("no records should be emitted from an unparsed file, got %+v", names(out))
	}
}

func TestIsRequirementsTxt(t *testing.T) {
	cases := map[string]bool{
		"requirements.txt":      true,
		"requirements-dev.txt":  true,
		"requirements_test.txt": true,
		"dev-requirements.txt":  true,
		"notes.txt":             false,
		"requirements.md":       false,
	}
	for in, want := range cases {
		if got := IsRequirementsTxt(in); got != want {
			t.Errorf("IsRequirementsTxt(%q) = %v, want %v", in, got, want)
		}
	}
}

func names(rs []model.Record) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.PackageName+"@"+r.Version)
	}
	return out
}
