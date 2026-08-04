// Package swift scans Swift Package Manager and CocoaPods artifacts.
//
// Two file shapes, two emitted ecosystems:
//
//   - Package.resolved — Swift PM's resolved pin list. Both the v1 shape
//     (pins nested under "object") and the v2/v3 flat shape are handled.
//     Packages are identified by their source URL with the scheme and
//     ".git" suffix trimmed, which is how advisory feeds name Swift
//     packages; the short identity is used as a fallback.
//   - Podfile.lock — CocoaPods' resolved pod list, read from the PODS
//     section. Subspecs ("Firebase/Core") are preserved as written.
//
// Both files are resolved lock state, so records are high confidence.
package swift

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

const (
	EcosystemSwift     = model.EcosystemSwift
	EcosystemCocoaPods = model.EcosystemCocoaPods
)

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsPackageResolved(base string) bool { return base == "Package.resolved" }
func IsPodfileLock(base string) bool     { return base == "Podfile.lock" }

// packageResolved covers both schema generations. v1 nests pins under
// "object"; v2 and v3 hoist them to the top level.
type packageResolved struct {
	Version int              `json:"version"`
	Pins    []resolvedPin    `json:"pins"`
	Object  *resolvedPinList `json:"object"`
}

type resolvedPinList struct {
	Pins []resolvedPin `json:"pins"`
}

type resolvedPin struct {
	// v1 spells these "package" and "repositoryURL"; v2+ uses
	// "identity" and "location".
	Package       string `json:"package"`
	Identity      string `json:"identity"`
	RepositoryURL string `json:"repositoryURL"`
	Location      string `json:"location"`
	State         struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
		Branch   string `json:"branch"`
	} `json:"state"`
}

func (s *Scanner) ScanPackageResolved(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var resolved packageResolved
	if err := json.Unmarshal(data, &resolved); err != nil {
		s.note(path, "unparseable Package.resolved: "+err.Error())
		return nil
	}
	pins := resolved.Pins
	if len(pins) == 0 && resolved.Object != nil {
		pins = resolved.Object.Pins
	}
	projectPath := filepath.Dir(path)
	for _, pin := range pins {
		name := packageURLName(firstNonEmpty(pin.Location, pin.RepositoryURL))
		if name == "" {
			name = firstNonEmpty(pin.Identity, pin.Package)
		}
		if name == "" {
			continue
		}
		version := pin.State.Version
		confidence := "high"
		if version == "" {
			// A branch or revision pin has no semantic version. The
			// revision still identifies the code, but it will not match a
			// version-keyed catalog entry.
			version = pin.State.Revision
			confidence = "low"
		}
		if version == "" {
			continue
		}
		r := base
		r.Ecosystem = EcosystemSwift
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

// ScanPodfileLock reads the PODS section of a Podfile.lock. The file is
// YAML, but only one section shape matters, so it is read line-wise
// rather than through a general YAML parser.
func (s *Scanner) ScanPodfileLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	inPods := false
	seen := make(map[string]struct{})
	for sc.Scan() {
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		// Section headers sit at column zero.
		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "-") {
			inPods = strings.HasPrefix(raw, "PODS:")
			continue
		}
		if !inPods || !strings.HasPrefix(trimmed, "- ") {
			continue
		}
		// Entries look like "- Alamofire (5.6.4)" or, for a pod with its
		// own dependencies, "- Firebase/Core (10.0.0):". Nested
		// dependency lines lack the parenthesised version and are skipped.
		entry := strings.TrimSuffix(strings.TrimPrefix(trimmed, "- "), ":")
		name, version, ok := splitPodEntry(entry)
		if !ok {
			continue
		}
		key := name + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		r := base
		r.Ecosystem = EcosystemCocoaPods
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
	return nil
}

// splitPodEntry pulls "Name (1.2.3)" apart. Version constraints such as
// "(~> 1.2)" are not exact versions and are rejected.
func splitPodEntry(entry string) (name, version string, ok bool) {
	open := strings.LastIndex(entry, " (")
	if open < 0 || !strings.HasSuffix(entry, ")") {
		return "", "", false
	}
	name = strings.TrimSpace(entry[:open])
	version = strings.TrimSpace(entry[open+2 : len(entry)-1])
	if name == "" || version == "" {
		return "", "", false
	}
	if strings.ContainsAny(version, "~><= ") {
		return "", "", false
	}
	return name, version, true
}

// packageURLName trims a source URL down to the host/path form used to
// identify Swift packages (e.g. "github.com/Alamofire/Alamofire").
func packageURLName(location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	for _, scheme := range []string{"https://", "http://", "git://", "ssh://"} {
		location = strings.TrimPrefix(location, scheme)
	}
	// scp-style remotes: git@github.com:owner/repo.git
	if at := strings.Index(location, "@"); at >= 0 && !strings.Contains(location[:at], "/") {
		location = location[at+1:]
		location = strings.Replace(location, ":", "/", 1)
	}
	location = strings.TrimSuffix(location, ".git")
	location = strings.TrimSuffix(location, "/")
	if strings.HasPrefix(location, "file/") || strings.HasPrefix(location, "/") {
		return ""
	}
	return location
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
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
