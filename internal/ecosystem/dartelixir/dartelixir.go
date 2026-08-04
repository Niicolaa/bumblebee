// Package dartelixir scans Dart's pubspec.lock and Elixir's mix.lock.
//
// They share a package because both are small, line-structured formats
// with no shared machinery elsewhere in the tree.
//
// pubspec.lock is YAML, but the shape needed is regular: a `packages:`
// map whose entries carry `version: "x.y.z"` and a `source:`. It is read
// line-wise, tracking indentation, rather than by adding a YAML parser.
//
// mix.lock is an Elixir map literal, one entry per line:
//
//	"jason": {:hex, :jason, "1.4.1", "hash", [:mix], [...], "hexpm", "hash"},
//
// The name and version are the second and third elements of the tuple
// for :hex packages. Non-hex entries (:git, :path) name a dependency
// with no registry version.
package dartelixir

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsPubspecLock(base string) bool { return base == "pubspec.lock" }
func IsMixLock(base string) bool     { return base == "mix.lock" }

// ScanPubspecLock parses a Dart pubspec.lock.
func (s *Scanner) ScanPubspecLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)

	type pending struct {
		name    string
		version string
		source  string
		dep     string
	}
	var cur pending
	inPackages := false
	flush := func() {
		if cur.name == "" {
			return
		}
		confidence := "high"
		// A path or git dependency has no pub.dev version to match.
		if cur.version == "" || (cur.source != "" && cur.source != "hosted") {
			confidence = "low"
		}
		scope := ""
		switch cur.dep {
		case "direct main":
			scope = "prod"
		case "direct dev":
			scope = "dev"
		}
		r := base
		r.Ecosystem = model.EcosystemPub
		r.PackageName = cur.name
		r.NormalizedName = strings.ToLower(cur.name)
		r.Version = cur.version
		r.ProjectPath = projectPath
		r.InstallScope = scope
		r.PackageManager = "pub"
		r.SourceType = "pub-pubspec-lock"
		r.SourceFile = path
		r.Confidence = confidence
		s.Emit(r)
		cur = pending{}
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))

		if indent == 0 {
			flush()
			inPackages = strings.HasPrefix(trimmed, "packages:")
			continue
		}
		if !inPackages {
			continue
		}
		// A package name sits at two spaces: "  crypto:".
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			flush()
			cur.name = strings.TrimSuffix(trimmed, ":")
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch strings.TrimSpace(key) {
		case "version":
			cur.version = value
		case "source":
			cur.source = value
		case "dependency":
			cur.dep = value
		}
	}
	flush()
	return sc.Err()
}

// mixHexEntry matches a :hex tuple: {:hex, :jason, "1.4.1", ...}.
var mixHexEntry = regexp.MustCompile(`\{:hex,\s*:([A-Za-z0-9_]+),\s*"([^"]+)"`)

// mixOtherEntry matches the name of a non-hex entry: "dep": {:git, ...}.
var mixOtherEntry = regexp.MustCompile(`^\s*"([^"]+)":\s*\{:([a-z]+)`)

// ScanMixLock parses an Elixir mix.lock.
func (s *Scanner) ScanMixLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		var name, version, confidence string
		if m := mixHexEntry.FindStringSubmatch(line); m != nil {
			name, version, confidence = m[1], m[2], "high"
		} else if m := mixOtherEntry.FindStringSubmatch(line); m != nil {
			// :git / :path dependency — real, but no hex.pm version.
			name, version, confidence = m[1], "", "low"
		} else {
			continue
		}
		key := name + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		r := base
		r.Ecosystem = model.EcosystemHex
		r.PackageName = name
		r.NormalizedName = strings.ToLower(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "mix"
		r.SourceType = "hex-mix-lock"
		r.SourceFile = path
		r.Confidence = confidence
		s.Emit(r)
	}
	return sc.Err()
}

func (s *Scanner) readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	limit := s.MaxFileSize
	if limit <= 0 {
		limit = 5 * 1024 * 1024
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) == limit {
		if s.Diag != nil {
			s.Diag("warn", path, "file exceeds max-file-size; not parsed")
		}
		return nil, errors.New("file exceeds max-file-size")
	}
	return data, nil
}
