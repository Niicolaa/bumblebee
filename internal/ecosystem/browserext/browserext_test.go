package browserext

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestIsChromiumExtensionManifest(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
	}{
		{"/u/Library/Application Support/Google/Chrome/Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/1.0.0_0/manifest.json", true},
		{"/u/.config/google-chrome/Profile 1/Extensions/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/2.3.4/manifest.json", true},
		// id too short
		{"/u/Chrome/Default/Extensions/aa/1.0/manifest.json", false},
		// id has invalid character (only a-p allowed)
		{"/u/Chrome/Default/Extensions/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/1.0/manifest.json", false},
		// wrong leaf
		{"/u/Chrome/Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/1.0/foo.json", false},
		// missing Extensions parent
		{"/u/Chrome/Default/Other/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/1.0/manifest.json", false},
	}
	for _, c := range cases {
		ok, _, _, _ := IsChromiumExtensionManifest(c.path)
		if ok != c.ok {
			t.Errorf("IsChromiumExtensionManifest(%q) = %v, want %v", c.path, ok, c.ok)
		}
	}
}

func TestScanChromiumExtension_PlainName(t *testing.T) {
	dir := t.TempDir()
	extID := "abcdefghijklmnopabcdefghijklmnop" // 32 chars in a..p
	profileDir := filepath.Join(dir, "Library", "Application Support", "Google", "Chrome", "Default")
	versionDir := filepath.Join(profileDir, "Extensions", extID, "1.2.3_0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(versionDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"name":"My Extension","version":"1.2.3","manifest_version":3}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanChromiumExtension(manifestPath, extID, versionDir, profileDir, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 record, got %d", len(out))
	}
	r := out[0]
	if r.Ecosystem != Ecosystem {
		t.Errorf("ecosystem=%q", r.Ecosystem)
	}
	if r.PackageName != "My Extension" || r.Version != "1.2.3" {
		t.Errorf("record fields: %+v", r)
	}
	if r.NormalizedName != extID {
		t.Errorf("normalized_name=%q, want %q", r.NormalizedName, extID)
	}
	if r.SourceType != "browser-extension" {
		t.Errorf("source_type=%q", r.SourceType)
	}
	if r.RootKind != model.RootKindBrowserExtension {
		t.Errorf("root_kind=%q", r.RootKind)
	}
	if r.PackageManager != "chromium-extension" {
		t.Errorf("packageManager=%q (want chromium-extension)", r.PackageManager)
	}
	if r.Confidence != "high" {
		t.Errorf("confidence=%q", r.Confidence)
	}
}

func TestScanChromiumExtension_LocalizedName(t *testing.T) {
	dir := t.TempDir()
	extID := "abcdefghijklmnopabcdefghijklmnop"
	profileDir := filepath.Join(dir, "BraveSoftware", "Brave-Browser", "Default")
	versionDir := filepath.Join(profileDir, "Extensions", extID, "4.5.6_0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(versionDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"name":"__MSG_extName__","version":"4.5.6","default_locale":"en"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	localesDir := filepath.Join(versionDir, "_locales", "en")
	if err := os.MkdirAll(localesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localesDir, "messages.json"),
		[]byte(`{"extName":{"message":"Localized Brave Extension"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanChromiumExtension(manifestPath, extID, versionDir, profileDir, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 record, got %d", len(out))
	}
	if out[0].PackageName != "Localized Brave Extension" {
		t.Errorf("locale resolution: %+v", out[0])
	}
	if out[0].PackageManager != "chromium-extension" {
		t.Errorf("packageManager=%q (want chromium-extension)", out[0].PackageManager)
	}
}

func TestIsFirefoxExtensionsJSON(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
	}{
		{"/u/Library/Application Support/Firefox/Profiles/abcd.default/extensions.json", true},
		{"/u/.mozilla/firefox/abcd.default-release/extensions.json", true},
		{"/u/snap/firefox/common/.mozilla/firefox/abcd.default/extensions.json", true},
		{"/u/.var/app/org.mozilla.firefox/.mozilla/firefox/abcd.default/extensions.json", true},
		{"/u/.librewolf/abcd.default/extensions.json", true},
		{"/u/.waterfox/abcd.default/extensions.json", true},
		{"/u/Library/Application Support/LibreWolf/Profiles/x.default/extensions.json", true},
		{"/u/Library/Application Support/Google/Chrome/Default/extensions.json", false},
		{"/u/random/extensions.json", false},
	}
	for _, c := range cases {
		got := IsFirefoxExtensionsJSON(c.path)
		if got != c.ok {
			t.Errorf("IsFirefoxExtensionsJSON(%q) = %v, want %v", c.path, got, c.ok)
		}
	}
}

func TestScanFirefoxExtensions(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "Library", "Application Support", "Firefox", "Profiles", "abcd.default")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(profileDir, "extensions.json")
	body := `{
  "addons": [
    {"id":"ublock@example.com","version":"1.50.0","type":"extension","active":true,"defaultLocale":{"name":"uBlock Origin"}},
    {"id":"theme@example.com","version":"1.0","type":"theme","active":true,"defaultLocale":{"name":"Sleek Theme"}},
    {"id":"plain@example.com","version":"2.0","type":"extension","active":true}
  ]
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanFirefoxExtensions(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 records (themes skipped), got %d", len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NormalizedName < out[j].NormalizedName })
	if out[0].PackageName != "plain@example.com" {
		t.Errorf("fallback to id when defaultLocale.name missing: %+v", out[0])
	}
	if out[1].PackageName != "uBlock Origin" || out[1].Version != "1.50.0" {
		t.Errorf("first ext: %+v", out[1])
	}
	if out[1].PackageManager != "firefox-extension" {
		t.Errorf("packageManager=%q (want firefox-extension)", out[1].PackageManager)
	}
	if out[1].RootKind != model.RootKindBrowserExtension {
		t.Errorf("root_kind=%q", out[1].RootKind)
	}
}

func TestScanChromiumExtension_LocaleTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	extID := "abcdefghijklmnopabcdefghijklmnop"
	profileDir := filepath.Join(dir, "Google", "Chrome", "Default")
	versionDir := filepath.Join(profileDir, "Extensions", extID, "1.0_0")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A file outside the extension directory that a traversing
	// default_locale would otherwise reach.
	secretDir := filepath.Join(dir, "secret", "_locales", "x")
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "messages.json"), []byte(`{"extName":{"message":"LEAKED"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Relative escape from versionDir/_locales back down into dir/secret/_locales/x.
	escape := filepath.Join("..", "..", "..", "..", "..", "secret", "_locales", "x")
	manifestPath := filepath.Join(versionDir, "manifest.json")
	manifest := `{"name":"__MSG_extName__","version":"1.0","default_locale":` + strconv.Quote(escape) + `}`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanChromiumExtension(manifestPath, extID, versionDir, profileDir, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 record, got %d", len(out))
	}
	if out[0].PackageName == "LEAKED" {
		t.Fatalf("traversing default_locale leaked out-of-tree content: %+v", out[0])
	}
	if out[0].PackageName != "__MSG_extName__" {
		t.Errorf("package_name=%q, want the unresolved placeholder", out[0].PackageName)
	}
}

func TestValidLocaleDir(t *testing.T) {
	good := []string{"en", "en_US", "pt-BR", "zh_CN"}
	for _, l := range good {
		if !validLocaleDir(l) {
			t.Errorf("validLocaleDir(%q) = false, want true", l)
		}
	}
	bad := []string{"", "..", "../en", "en/../..", `..\en`, "/etc", "C:", "a b", strings.Repeat("a", 36)}
	for _, l := range bad {
		if validLocaleDir(l) {
			t.Errorf("validLocaleDir(%q) = true, want false", l)
		}
	}
}
