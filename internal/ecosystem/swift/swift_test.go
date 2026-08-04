package swift

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func scan(t *testing.T, name, content string, fn func(*Scanner, string, model.Record) error) []model.Record {
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

func TestScanPackageResolvedV2(t *testing.T) {
	got := scan(t, "Package.resolved", `{
  "pins": [
    {
      "identity": "alamofire",
      "kind": "remoteSourceControl",
      "location": "https://github.com/Alamofire/Alamofire.git",
      "state": { "revision": "abc123", "version": "5.8.1" }
    }
  ],
  "version": 2
}`, (*Scanner).ScanPackageResolved)

	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(got), got)
	}
	r := got[0]
	// Advisory feeds identify Swift packages by their source URL.
	if r.PackageName != "github.com/Alamofire/Alamofire" {
		t.Errorf("package = %q, want the trimmed source URL", r.PackageName)
	}
	if r.Version != "5.8.1" || r.Confidence != "high" {
		t.Errorf("version/confidence = %q/%q", r.Version, r.Confidence)
	}
	if r.Ecosystem != model.EcosystemSwift {
		t.Errorf("ecosystem = %q", r.Ecosystem)
	}
}

func TestScanPackageResolvedV1(t *testing.T) {
	got := scan(t, "Package.resolved", `{
  "object": {
    "pins": [
      {
        "package": "SnapKit",
        "repositoryURL": "https://github.com/SnapKit/SnapKit.git",
        "state": { "revision": "def456", "version": "5.6.0" }
      }
    ]
  },
  "version": 1
}`, (*Scanner).ScanPackageResolved)

	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].PackageName != "github.com/SnapKit/SnapKit" {
		t.Errorf("package = %q", got[0].PackageName)
	}
}

// A branch pin has no release version; the revision still identifies the
// code but cannot match a version-keyed catalog entry.
func TestScanPackageResolvedBranchPinIsLowConfidence(t *testing.T) {
	got := scan(t, "Package.resolved", `{
  "pins": [
    { "identity": "x", "location": "https://github.com/o/x.git",
      "state": { "revision": "deadbeef", "branch": "main" } }
  ],
  "version": 2
}`, (*Scanner).ScanPackageResolved)

	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].Version != "deadbeef" || got[0].Confidence != "low" {
		t.Errorf("version/confidence = %q/%q, want revision/low", got[0].Version, got[0].Confidence)
	}
}

func TestScanPodfileLock(t *testing.T) {
	got := scan(t, "Podfile.lock", `PODS:
  - Alamofire (5.8.1)
  - Firebase/Core (10.19.0):
    - Firebase/CoreOnly
  - Firebase/CoreOnly (10.19.0)

DEPENDENCIES:
  - Alamofire

SPEC CHECKSUMS:
  Alamofire: 3ca42e259043ee0dc5c0cdd76c4bc568b8e42af7

COCOAPODS: 1.14.3
`, (*Scanner).ScanPodfileLock)

	byName := map[string]model.Record{}
	for _, r := range got {
		byName[r.PackageName] = r
	}
	if len(byName) != 3 {
		t.Fatalf("got %d pods, want 3: %+v", len(byName), got)
	}
	if r := byName["Alamofire"]; r.Version != "5.8.1" {
		t.Errorf("Alamofire version = %q", r.Version)
	}
	// Subspecs keep their slash-qualified name.
	sub, ok := byName["Firebase/Core"]
	if !ok {
		t.Fatal("subspec Firebase/Core missing")
	}
	if sub.Version != "10.19.0" {
		t.Errorf("Firebase/Core version = %q", sub.Version)
	}
	if sub.Ecosystem != model.EcosystemCocoaPods {
		t.Errorf("ecosystem = %q", sub.Ecosystem)
	}
	// The DEPENDENCIES section lists names without versions and must not
	// produce records.
	for _, r := range got {
		if r.Version == "" {
			t.Errorf("record %q has no version", r.PackageName)
		}
	}
}

func TestSplitPodEntryRejectsConstraints(t *testing.T) {
	if _, _, ok := splitPodEntry("Alamofire (~> 5.0)"); ok {
		t.Error("a version constraint is not an exact version")
	}
	name, version, ok := splitPodEntry("Alamofire (5.8.1)")
	if !ok || name != "Alamofire" || version != "5.8.1" {
		t.Errorf("splitPodEntry = %q %q %v", name, version, ok)
	}
}

func TestPackageURLName(t *testing.T) {
	cases := map[string]string{
		"https://github.com/Alamofire/Alamofire.git": "github.com/Alamofire/Alamofire",
		"git@github.com:owner/repo.git":              "github.com/owner/repo",
		"https://gitlab.com/g/p":                     "gitlab.com/g/p",
		"":                                           "",
	}
	for in, want := range cases {
		if got := packageURLName(in); got != want {
			t.Errorf("packageURLName(%q) = %q, want %q", in, got, want)
		}
	}
}
