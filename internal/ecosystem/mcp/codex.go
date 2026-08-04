package mcp

import (
	"path/filepath"

	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/toml"
)

// Codex writes its MCP host configuration as TOML rather than JSON:
//
//	[mcp_servers.playwright]
//	command = "npx"
//	args = ["-y", "@playwright/mcp@latest"]
//
// This was previously out of scope purely because there was no TOML
// reader. Server entries are converted to the same serverEntry shape the
// JSON path uses, so both formats yield identical records.
//
// As with every other MCP source, `env` values and key names are dropped
// rather than recorded.

// IsCodexConfigTOML reports whether path is a Codex host config. The
// basename `config.toml` is far too generic on its own, so the immediate
// parent must be `.codex`.
func IsCodexConfigTOML(path string) bool {
	if filepath.Base(path) != "config.toml" {
		return false
	}
	return filepath.Base(filepath.Dir(path)) == ".codex"
}

func (s *Scanner) ScanCodexConfigTOML(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	root, err := toml.Parse(data)
	if err != nil {
		if s.Diag != nil {
			s.Diag("warn", path, "parse Codex MCP config: "+err.Error())
		}
		return nil
	}
	// Codex has used both spellings across releases.
	table, ok := toml.Table(root["mcp_servers"])
	if !ok {
		table, ok = toml.Table(root["mcpServers"])
	}
	if !ok || len(table) == 0 {
		if s.Diag != nil {
			s.Diag("info", path, "no MCP servers parsed")
		}
		return nil
	}

	servers := make(map[string]serverEntry, len(table))
	for id, raw := range table {
		entry, ok := toml.Table(raw)
		if !ok {
			continue
		}
		srv := serverEntry{}
		srv.Command, _ = toml.String(entry["command"])
		srv.Args = toml.Strings(entry["args"])
		srv.URL, _ = toml.String(entry["url"])
		srv.Type, _ = toml.String(entry["type"])
		// Same widening rule as the flat JSON envelope: an entry must
		// carry enough signal to be a server definition.
		if srv.Command == "" && srv.URL == "" && len(srv.Args) == 0 && srv.Type == "" {
			continue
		}
		servers[id] = srv
	}
	if len(servers) == 0 {
		return nil
	}
	s.emitServers(servers, base, path, filepath.Dir(path))
	return nil
}
