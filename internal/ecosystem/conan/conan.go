// Package conan scans C/C++ `conan.lock` files.
//
// Two lock generations are handled. Conan 2.x lists requirement
// references in flat arrays:
//
//	{"version": "0.5", "requires": ["zlib/1.2.11#rev%timestamp", ...]}
//
// Conan 1.x nests them in a graph:
//
//	{"graph_lock": {"nodes": {"1": {"ref": "zlib/1.2.11@user/channel#rev"}}}}
//
// In both cases a reference is "name/version" optionally followed by
// "@user/channel", "#recipe-revision", and "%timestamp"; only the name and
// version are recorded.
package conan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

const Ecosystem = model.EcosystemConan

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsConanLock(base string) bool { return base == "conan.lock" }

type conanLock struct {
	// Conan 2.x
	Requires       []string `json:"requires"`
	BuildRequires  []string `json:"build_requires"`
	PythonRequires []string `json:"python_requires"`
	// Conan 1.x
	GraphLock struct {
		Nodes map[string]struct {
			Ref string `json:"ref"`
		} `json:"nodes"`
	} `json:"graph_lock"`
}

func (s *Scanner) ScanConanLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var lock conanLock
	if err := json.Unmarshal(data, &lock); err != nil {
		s.note(path, "unparseable conan.lock: "+err.Error())
		return nil
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	emit := func(ref, scope string) {
		name, version, ok := splitReference(ref)
		if !ok {
			return
		}
		key := name + "\x00" + version
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}

		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = name
		r.NormalizedName = strings.ToLower(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "conan"
		r.SourceType = "conan-lock"
		r.SourceFile = path
		r.InstallScope = scope
		r.Confidence = "high"
		s.Emit(r)
	}

	for _, ref := range lock.Requires {
		emit(ref, "")
	}
	for _, ref := range lock.BuildRequires {
		emit(ref, "build")
	}
	for _, ref := range lock.PythonRequires {
		emit(ref, "build")
	}
	for _, node := range lock.GraphLock.Nodes {
		emit(node.Ref, "")
	}
	return nil
}

// splitReference pulls the name and version out of a Conan reference.
// Everything from the first '@', '#', or '%' onward is metadata about
// where the recipe came from rather than package identity.
func splitReference(ref string) (name, version string, ok bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", "", false
	}
	for _, sep := range []string{"%", "#", "@"} {
		if i := strings.Index(ref, sep); i >= 0 {
			ref = ref[:i]
		}
	}
	name, version, found := strings.Cut(ref, "/")
	if !found || name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

func (s *Scanner) note(path, msg string) {
	if s.Diag != nil {
		s.Diag("warn", path, msg)
	}
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
