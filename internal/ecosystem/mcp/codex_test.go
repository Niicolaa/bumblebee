package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

// writeCodexConfig places config.toml inside a .codex directory, which is
// what the path predicate requires.
func writeCodexConfig(t *testing.T, content string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIsCodexConfigTOML(t *testing.T) {
	if !IsCodexConfigTOML(filepath.Join("home", ".codex", "config.toml")) {
		t.Error(".codex/config.toml should match")
	}
	// config.toml is far too generic a name to match anywhere.
	for _, no := range []string{
		filepath.Join("proj", "config.toml"),
		filepath.Join("home", ".cargo", "config.toml"),
		filepath.Join("home", ".codex", "other.toml"),
	} {
		if IsCodexConfigTOML(no) {
			t.Errorf("IsCodexConfigTOML(%q) = true", no)
		}
	}
}

func TestScanCodexConfigTOML(t *testing.T) {
	path := writeCodexConfig(t, `model = "o3"

[mcp_servers.playwright]
command = "npx"
args = ["-y", "@playwright/mcp@latest"]

[mcp_servers.local]
command = "/usr/local/bin/my-server"
`)
	var got []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { got = append(got, r) },
		Diag:        func(level, path, msg string) {},
	}
	if err := s.ScanCodexConfigTOML(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(got), got)
	}

	byServer := map[string]model.Record{}
	for _, r := range got {
		byServer[r.ServerName] = r
	}
	pw, ok := byServer["playwright"]
	if !ok {
		t.Fatal("playwright server missing")
	}
	// The npx spec should be resolved the same way the JSON path does it.
	if pw.PackageName != "@playwright/mcp" {
		t.Errorf("package = %q, want the npm spec resolved", pw.PackageName)
	}
	if pw.Ecosystem != model.EcosystemMCP {
		t.Errorf("ecosystem = %q", pw.Ecosystem)
	}
	if pw.RootKind != model.RootKindMCPConfig {
		t.Errorf("root kind = %q", pw.RootKind)
	}
	if _, ok := byServer["local"]; !ok {
		t.Error("local server missing")
	}
}

// env values and key names are dropped for every MCP source; TOML is no
// exception.
func TestScanCodexConfigTOMLDropsEnv(t *testing.T) {
	path := writeCodexConfig(t, `[mcp_servers.secretive]
command = "npx"
args = ["-y", "some-pkg"]

[mcp_servers.secretive.env]
API_TOKEN = "sk-live-do-not-record"
`)
	var got []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { got = append(got, r) }}
	if err := s.ScanCodexConfigTOML(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	for _, r := range got {
		for _, field := range []string{r.PackageName, r.RequestedSpec, r.ServerName, r.Version} {
			if field == "sk-live-do-not-record" || field == "API_TOKEN" {
				t.Errorf("env material leaked into a record: %+v", r)
			}
		}
	}
}

func TestScanCodexConfigTOMLNoServers(t *testing.T) {
	path := writeCodexConfig(t, "model = \"o3\"\n")
	var got []model.Record
	var infos int
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { got = append(got, r) },
		Diag:        func(level, path, msg string) { infos++ },
	}
	if err := s.ScanCodexConfigTOML(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d records from a config with no servers", len(got))
	}
	if infos == 0 {
		t.Error("expected an informational diagnostic")
	}
}

func TestScanCodexConfigTOMLMalformed(t *testing.T) {
	path := writeCodexConfig(t, "[mcp_servers.broken\ncommand = ")
	var warned bool
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(model.Record) {},
		Diag:        func(level, path, msg string) { warned = true },
	}
	if err := s.ScanCodexConfigTOML(path, model.Record{}); err != nil {
		t.Fatalf("malformed TOML should warn, not error: %v", err)
	}
	if !warned {
		t.Error("expected a warn diagnostic")
	}
}
