// Package pub scans Dart/Flutter `pubspec.lock` files.
//
// pubspec.lock is YAML, but only one nesting shape matters — the
// `packages:` map, whose entries carry a `version:` and a `source:`. The
// file is read line-wise against that shape rather than through a general
// YAML parser.
//
// Only hosted packages are recorded with high confidence; `path` and `git`
// sources identify local or VCS code whose version field is not a registry
// release.
package pub

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

const Ecosystem = model.EcosystemPub

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsPubspecLock(base string) bool { return base == "pubspec.lock" }

func (s *Scanner) ScanPubspecLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)

	type pending struct {
		name       string
		version    string
		source     string
		dependency string
	}
	var cur pending
	flush := func() {
		if cur.name == "" || cur.version == "" {
			return
		}
		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = cur.name
		r.NormalizedName = strings.ToLower(cur.name)
		r.Version = cur.version
		r.ProjectPath = projectPath
		r.PackageManager = "pub"
		r.SourceType = "pub-lock"
		r.SourceFile = path
		switch cur.dependency {
		case "direct main", "direct dev":
			direct := true
			r.DirectDependency = &direct
			if cur.dependency == "direct dev" {
				r.InstallScope = "dev"
			}
		case "transitive":
			direct := false
			r.DirectDependency = &direct
			r.InstallScope = "indirect"
		}
		if cur.source == "hosted" {
			r.Confidence = "high"
		} else {
			// path/git/sdk sources are not registry releases.
			r.InstallScope = "local"
			r.Confidence = "low"
		}
		s.Emit(r)
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	inPackages := false
	for sc.Scan() {
		raw := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		trimmed := strings.TrimSpace(raw)

		if indent == 0 {
			flush()
			cur = pending{}
			inPackages = strings.HasPrefix(trimmed, "packages:")
			continue
		}
		if !inPackages {
			continue
		}
		// A two-space-indented "name:" opens a new package entry.
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			flush()
			cur = pending{name: strings.TrimSuffix(trimmed, ":")}
			continue
		}
		if cur.name == "" || indent < 4 {
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if value == "" {
			continue
		}
		// Only read these at the entry's own level; `description:` nests a
		// `name:` one level deeper that must not overwrite the entry name.
		if indent != 4 {
			continue
		}
		switch key {
		case "version":
			cur.version = value
		case "source":
			cur.source = value
		case "dependency":
			cur.dependency = value
		}
	}
	flush()
	return nil
}

func (s *Scanner) readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if s.MaxFileSize > 0 && info.Size() > s.MaxFileSize {
		if s.Diag != nil {
			s.Diag("warn", path, fmt.Sprintf("skipping: size %d exceeds max %d", info.Size(), s.MaxFileSize))
		}
		return nil, fmt.Errorf("file %s exceeds max size %d", path, s.MaxFileSize)
	}
	return io.ReadAll(f)
}
