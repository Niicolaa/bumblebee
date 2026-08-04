package editorext

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestIsExtensionPackageJSON(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"/home/u/.vscode/extensions/ms-python.python-2024.0.0/package.json", true},
		{"/home/u/.cursor/extensions/some.ext-1.0.0/package.json", true},
		{"/home/u/.windsurf-server/extensions/x.y-1.0.0/package.json", true},
		// Remote/SSH server trees for the remaining editors: a remote
		// install is still an installed extension.
		{"/home/u/.vscodium-server/extensions/x.y-1.0.0/package.json", true},
		{"/home/u/.vscode-server-insiders/extensions/x.y-1.0.0/package.json", true},
		{"/home/u/.vscode-insiders-server/extensions/x.y-1.0.0/package.json", true},
		{"/home/u/proj/node_modules/lodash/package.json", false},
		{"/home/u/.vscode/extensions/somefile.txt", false},
	}
	for _, c := range cases {
		ok, _, _ := IsExtensionPackageJSON(c.in)
		if ok != c.ok {
			t.Errorf("IsExtensionPackageJSON(%q) = %v, want %v", c.in, ok, c.ok)
		}
	}
}

// The remote server trees must report the same host as their local
// counterpart, so a fleet query for "vscodium extensions" does not
// silently miss every remote install.
func TestHostFromExtRootCoversServerTrees(t *testing.T) {
	cases := map[string]string{
		"/home/u/.vscodium/extensions":               "vscodium",
		"/home/u/.vscodium-server/extensions":        "vscodium",
		"/home/u/.cursor-server/extensions":          "cursor",
		"/home/u/.windsurf-server/extensions":        "windsurf",
		"/home/u/.vscode-server-insiders/extensions": "vscode",
		"/home/u/.vscode-insiders-server/extensions": "vscode",
	}
	for in, want := range cases {
		if got := hostFromExtRoot(in); got != want {
			t.Errorf("hostFromExtRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScanExtension(t *testing.T) {
	dir := t.TempDir()
	extRoot := filepath.Join(dir, ".cursor", "extensions")
	extDir := filepath.Join(extRoot, "anysphere.cursor-ai-1.2.3")
	if err := os.MkdirAll(extDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pjPath := filepath.Join(extDir, "package.json")
	body := `{"name":"cursor-ai","version":"1.2.3","publisher":"anysphere","engines":{"vscode":"^1.80.0"}}`
	if err := os.WriteFile(pjPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanExtension(pjPath, extRoot, extDir, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1, got %d", len(out))
	}
	if out[0].PackageName != "anysphere.cursor-ai" || out[0].Version != "1.2.3" {
		t.Errorf("got %+v", out[0])
	}
	if out[0].PackageManager != "cursor" {
		t.Errorf("host=%q", out[0].PackageManager)
	}
}
