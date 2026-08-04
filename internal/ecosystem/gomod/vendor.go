package gomod

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

// Additional Go module sources beyond go.mod / go.sum.
//
//   - go.work.sum uses the same line format as go.sum and appears at the
//     root of a multi-module workspace.
//   - vendor/modules.txt records exactly which modules and versions were
//     vendored into the tree, which is the only inventory source for a
//     project built with -mod=vendor.

func IsGoWorkSum(base string) bool { return base == "go.work.sum" }

func (s *Scanner) ScanGoWorkSum(path string, base model.Record) error {
	return s.scanSumFile(path, "go-work-sum", base)
}

// IsVendorModulesTxt reports whether path is a `vendor/modules.txt`. The
// basename alone is too generic, so the immediate parent must be
// `vendor`.
func IsVendorModulesTxt(path string) bool {
	if filepath.Base(path) != "modules.txt" {
		return false
	}
	return filepath.Base(filepath.Dir(path)) == "vendor"
}

// ScanVendorModulesTxt parses the module header lines of a vendor manifest:
//
//	# github.com/foo/bar v1.2.3
//	## explicit; go 1.20
//	github.com/foo/bar/pkg
//
// Package lines (no leading '#') are ignored: they name importable
// packages inside an already-recorded module. A replace directive
// ("# mod v1 => ./local") records the original module coordinates, since
// that is the identity an advisory would name.
func (s *Scanner) ScanVendorModulesTxt(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	// modules.txt lives in <project>/vendor/, so the project is its
	// grandparent.
	projectPath := filepath.Dir(filepath.Dir(path))
	seen := make(map[string]struct{})

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// "##" lines are module annotations (explicit, go version), not
		// module declarations.
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		decl := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		if i := strings.Index(decl, "=>"); i >= 0 {
			decl = strings.TrimSpace(decl[:i])
		}
		fields := strings.Fields(decl)
		if len(fields) < 2 {
			continue
		}
		module, version := fields[0], fields[1]
		if !strings.HasPrefix(version, "v") {
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
		r.SourceType = "go-vendor-modules"
		r.SourceFile = path
		r.Confidence = "high"
		s.Emit(r)
	}
	return nil
}
