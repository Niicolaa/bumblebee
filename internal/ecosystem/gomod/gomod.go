// Package gomod scans Go module artifacts: go.sum, go.mod, go.work.sum,
// and vendor/modules.txt.
//
// go.sum is the most reliable inventory source because it lists exactly the
// modules at the versions Go fetched, with their content hashes. go.mod
// requirements are also recorded (lower-confidence: they may not all end up
// in the final build set).
//
// go.work.sum uses the identical line format to go.sum and covers a
// multi-module workspace, whose members are otherwise reported only if
// each member module's own go.sum happens to be under a configured root.
// vendor/modules.txt is the only inventory a vendored tree has: those
// trees carry no go.sum of their own, so without it a fully vendored
// repository reads as having no Go dependencies at all.
//
// go.work itself is not parsed: it holds `use` directives pointing at
// local directories and carries no module versions, so it cannot produce
// a package record.
//
// No `go` commands are executed. Dispatch is filename-based, so any
// `go.sum` / `go.mod` reachable from a configured root is parsed —
// including files inside the per-user module cache (`~/go/pkg/mod`)
// when `~/go` is a baseline root. The cache's source-file subtrees
// are not walked for anything beyond those two filenames.
package gomod

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

const Ecosystem = model.EcosystemGo

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsGoSum(base string) bool { return base == "go.sum" }
func IsGoMod(base string) bool { return base == "go.mod" }

// IsGoWorkSum reports whether a basename is a Go workspace sum file. Its
// line format is identical to go.sum.
func IsGoWorkSum(base string) bool { return base == "go.work.sum" }

// IsVendorModulesTxt returns true if path is a `vendor/modules.txt`. The
// parent directory must actually be named `vendor` — `modules.txt` is a
// generic enough name that matching it anywhere would misparse unrelated
// files.
func IsVendorModulesTxt(path string) bool {
	if filepath.Base(path) != "modules.txt" {
		return false
	}
	return filepath.Base(filepath.Dir(path)) == "vendor"
}

func (s *Scanner) ScanGoSum(path string, base model.Record) error {
	return s.scanSumFile(path, base, "go-sum", "high")
}

// ScanGoWorkSum parses a go.work.sum. Confidence is medium rather than
// high: a workspace sum accumulates hashes for the union of every member
// module's graph, so an entry is weaker evidence that this particular
// tree builds against that version than a single module's go.sum is.
func (s *Scanner) ScanGoWorkSum(path string, base model.Record) error {
	return s.scanSumFile(path, base, "go-work-sum", "medium")
}

func (s *Scanner) scanSumFile(path string, base model.Record, sourceType, confidence string) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		module := fields[0]
		version := fields[1]
		// Skip "module/go.mod" pseudo-entries; the module entry is enough.
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}
		key := module + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = module
		r.NormalizedName = strings.ToLower(module)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "go"
		r.SourceType = sourceType
		r.SourceFile = path
		r.Confidence = confidence
		s.Emit(r)
	}
	return nil
}

// ScanVendorModulesTxt parses a `vendor/modules.txt`. Module lines look
// like:
//
//	# github.com/foo/bar v1.2.3
//	## explicit; go 1.21
//	github.com/foo/bar/pkg
//
// Only the `# <module> <version>` lines carry identity, and a vendored
// tree is by definition present on disk at that version, so these are
// high confidence. `# <module> => <replacement>` replace directives are
// skipped: the left side is not what is vendored.
func (s *Scanner) ScanVendorModulesTxt(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(filepath.Dir(path)) // strip vendor/
	seen := make(map[string]struct{})

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		// "## explicit" annotations and bare package lines carry no version.
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "# "))
		if len(fields) != 2 {
			// Includes "=> replacement" forms and malformed lines.
			continue
		}
		module, version := fields[0], fields[1]
		if module == "" || !strings.HasPrefix(version, "v") {
			continue
		}
		key := module + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = module
		r.NormalizedName = strings.ToLower(module)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "go"
		r.SourceType = "go-vendor-modules-txt"
		r.SourceFile = path
		r.Confidence = "high"
		s.Emit(r)
	}
	return nil
}

func (s *Scanner) ScanGoMod(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	reqs := parseGoModRequires(data)
	for _, r := range reqs {
		if r.module == "" || r.version == "" {
			continue
		}
		rec := base
		rec.Ecosystem = Ecosystem
		rec.PackageName = r.module
		rec.NormalizedName = strings.ToLower(r.module)
		rec.Version = r.version
		rec.ProjectPath = projectPath
		rec.PackageManager = "go"
		rec.SourceType = "go-mod"
		rec.SourceFile = path
		if r.indirect {
			rec.InstallScope = "indirect"
			direct := false
			rec.DirectDependency = &direct
		} else {
			direct := true
			rec.DirectDependency = &direct
		}
		rec.Confidence = "medium"
		s.Emit(rec)
	}
	return nil
}

type goModRequire struct {
	module   string
	version  string
	indirect bool
}

func parseGoModRequires(data []byte) []goModRequire {
	var out []goModRequire
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	inBlock := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		comment := ""
		if i := strings.Index(line, "//"); i >= 0 {
			comment = strings.TrimSpace(line[i+2:])
			line = strings.TrimSpace(line[:i])
		}
		if !inBlock {
			if line == "require (" {
				inBlock = true
				continue
			}
			if strings.HasPrefix(line, "require ") {
				rest := strings.TrimSpace(strings.TrimPrefix(line, "require"))
				if r, ok := parseGoModRequireLine(rest, comment); ok {
					out = append(out, r)
				}
				continue
			}
			continue
		}
		if line == ")" {
			inBlock = false
			continue
		}
		if r, ok := parseGoModRequireLine(line, comment); ok {
			out = append(out, r)
		}
	}
	return out
}

func parseGoModRequireLine(line, comment string) (goModRequire, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return goModRequire{}, false
	}
	return goModRequire{
		module:   fields[0],
		version:  fields[1],
		indirect: strings.Contains(comment, "indirect"),
	}, true
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
