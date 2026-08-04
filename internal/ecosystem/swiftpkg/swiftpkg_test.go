package swiftpkg

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func run(t *testing.T, name, body string, fn func(*Scanner, string, model.Record) error) []model.Record {
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

// v2/v3 uses a top-level "pins" array with "identity".
func TestScanPackageResolvedV2(t *testing.T) {
	body := `{
  "pins" : [
    {
      "identity" : "alamofire",
      "kind" : "remoteSourceControl",
      "location" : "https://github.com/Alamofire/Alamofire.git",
      "state" : { "revision" : "abc", "version" : "5.9.1" }
    },
    {
      "identity" : "swift-log",
      "state" : { "revision" : "def", "branch" : "main" }
    }
  ],
  "version" : 2
}`
	out := run(t, "Package.resolved", body, (*Scanner).ScanPackageResolved)
	if len(out) != 2 {
		t.Fatalf("want 2 records, got %d: %+v", len(out), out)
	}
	if out[0].PackageName != "alamofire" || out[0].Version != "5.9.1" || out[0].Confidence != "high" {
		t.Errorf("alamofire: %+v", out[0])
	}
	// A branch pin has no released version to match an advisory against.
	if out[1].PackageName != "swift-log" || out[1].Version != "" || out[1].Confidence != "low" {
		t.Errorf("branch pin: %+v", out[1])
	}
	if out[0].Ecosystem != model.EcosystemSwift {
		t.Errorf("ecosystem=%q", out[0].Ecosystem)
	}
}

// v1 nests the pins under "object" and uses "package" for the name.
func TestScanPackageResolvedV1(t *testing.T) {
	body := `{
  "object": {
    "pins": [
      {
        "package": "Alamofire",
        "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
        "state": { "revision": "abc", "version": "5.4.0" }
      }
    ]
  },
  "version": 1
}`
	out := run(t, "Package.resolved", body, (*Scanner).ScanPackageResolved)
	if len(out) != 1 {
		t.Fatalf("want 1 record, got %d", len(out))
	}
	if out[0].PackageName != "Alamofire" || out[0].Version != "5.4.0" {
		t.Errorf("%+v", out[0])
	}
}

// Only top-level PODS entries are packages; the nested lines under them
// are that pod's dependencies and would double-count.
func TestScanPodfileLock(t *testing.T) {
	body := `PODS:
  - Alamofire (5.9.1)
  - Firebase/Core (10.29.0):
    - Firebase/CoreOnly
    - FirebaseAnalytics (~> 10.29.0)
  - FirebaseAnalytics (10.29.0)

DEPENDENCIES:
  - Alamofire

SPEC CHECKSUMS:
  Alamofire: 0123456789

COCOAPODS: 1.15.2
`
	out := run(t, "Podfile.lock", body, (*Scanner).ScanPodfileLock)
	if len(out) != 3 {
		t.Fatalf("want 3 records, got %d: %+v", len(out), names(out))
	}
	want := map[string]string{
		"Alamofire":         "5.9.1",
		"Firebase/Core":     "10.29.0",
		"FirebaseAnalytics": "10.29.0",
	}
	for _, r := range out {
		if w, ok := want[r.PackageName]; !ok || r.Version != w {
			t.Errorf("unexpected %s@%s", r.PackageName, r.Version)
		}
		if r.Ecosystem != model.EcosystemCocoaPods {
			t.Errorf("ecosystem=%q", r.Ecosystem)
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
