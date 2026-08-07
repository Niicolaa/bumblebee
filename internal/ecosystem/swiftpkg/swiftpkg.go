// Package swiftpkg scans Swift dependency state: SwiftPM's
// Package.resolved and CocoaPods' Podfile.lock.
//
// The two are separate ecosystems (`swift` and `cocoapods`) because a
// pod and a Swift package with the same name are different things and an
// advisory names one or the other.
//
// Package.resolved is JSON in two shapes: v1 wraps everything in
// `object.pins`, v2/v3 use a top-level `pins` array and rename
// `package` to `identity`. Both are handled.
//
// Podfile.lock is YAML, but the section this needs — `PODS:` — is a flat
// list of `- Name (version)` entries with nested dependency lines
// indented further. That is read line-wise rather than by adding a YAML
// parser, the same approach the Gemfile.lock reader already takes.
package swiftpkg

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/perplexityai/bumblebee/internal/ecosystem/safeopen"
	"github.com/perplexityai/bumblebee/internal/model"
)

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsPackageResolved(base string) bool { return base == "Package.resolved" }
func IsPodfileLock(base string) bool     { return base == "Podfile.lock" }

type packageResolved struct {
	Version int   `json:"version"`
	Pins    []pin `json:"pins"`
	Object  struct {
		Pins []pin `json:"pins"`
	} `json:"object"`
}

type pin struct {
	Identity      string `json:"identity"`
	Package       string `json:"package"`
	Location      string `json:"location"`
	RepositoryURL string `json:"repositoryURL"`
	State         struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
		Branch   string `json:"branch"`
	} `json:"state"`
}

// ScanPackageResolved parses a SwiftPM Package.resolved.
func (s *Scanner) ScanPackageResolved(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var doc packageResolved
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse Package.resolved: %w", err)
	}
	pins := doc.Pins
	if len(pins) == 0 {
		pins = doc.Object.Pins
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	for _, p := range pins {
		name := p.Identity
		if name == "" {
			name = p.Package
		}
		if name == "" {
			continue
		}
		// A pin to a branch or bare revision has no released version.
		version := p.State.Version
		confidence := "high"
		if version == "" {
			confidence = "low"
		}
		key := strings.ToLower(name) + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		r := base
		r.Ecosystem = model.EcosystemSwift
		r.PackageName = name
		r.NormalizedName = strings.ToLower(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "swiftpm"
		r.SourceType = "swift-package-resolved"
		r.SourceFile = path
		r.Confidence = confidence
		s.Emit(r)
	}
	return nil
}

// podLine matches a top-level PODS entry: `  - Alamofire (5.9.1)`.
// Nested dependency lines are indented further and are skipped, so a
// transitive dependency is not double-counted as its own pod.
var podLine = regexp.MustCompile(`^  - "?([^"\s(]+)"? \(([^)]+)\)`)

// ScanPodfileLock parses the PODS section of a Podfile.lock.
func (s *Scanner) ScanPodfileLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	inPods := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Section headers sit at column 0.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "-") {
			inPods = strings.HasPrefix(line, "PODS:")
			continue
		}
		if !inPods {
			continue
		}
		m := podLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// Subspecs ("Firebase/Core") belong to their parent pod.
		name := m[1]
		version := m[2]
		key := strings.ToLower(name) + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		r := base
		r.Ecosystem = model.EcosystemCocoaPods
		r.PackageName = name
		r.NormalizedName = strings.ToLower(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "cocoapods"
		r.SourceType = "cocoapods-podfile-lock"
		r.SourceFile = path
		r.Confidence = "high"
		s.Emit(r)
	}
	return sc.Err()
}

func (s *Scanner) readBounded(path string) ([]byte, error) {
	f, _, err := safeopen.Regular(path)
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
