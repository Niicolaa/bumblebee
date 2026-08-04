// Package maven scans Java/JVM dependency state.
//
// Sources:
//
//	*.gradle.lockfile      Gradle dependency locking — fully resolved
//	                       `group:artifact:version=configurations` lines
//	pom.xml                the declared <dependencies> block
//	~/.m2/repository/...   the local Maven repository, laid out as
//	                       <group path>/<artifact>/<version>/
//
// Confidence differs sharply between these. A Gradle lockfile and a
// local-repository directory both name an exact resolved version. A
// pom.xml does not: Maven resolves transitive dependencies and property
// placeholders (`${spring.version}`) at build time, so a pom lists only
// what the project asked for. Declared versions are therefore emitted at
// low confidence, and a version that is an unresolved property is
// emitted empty rather than as the literal `${...}` text.
//
// JAR/WAR/EAR archives are not opened. Reading embedded
// META-INF/maven/.../pom.properties would mean decompressing archives
// during a walk, which is a different cost and risk profile from the
// metadata reads everything else here does.
package maven

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

const Ecosystem = model.EcosystemMaven

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsPomXML(base string) bool { return base == "pom.xml" }

// IsGradleLockfile matches `gradle.lockfile` and the per-project
// `<name>.gradle.lockfile` form.
func IsGradleLockfile(base string) bool {
	return base == "gradle.lockfile" || strings.HasSuffix(base, ".gradle.lockfile")
}

// ScanGradleLockfile parses a Gradle dependency lockfile. Lines are
// `group:artifact:version=conf1,conf2`, with `empty=conf` markers for
// configurations that resolved to nothing.
func (s *Scanner) ScanGradleLockfile(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		coord := line
		if i := strings.Index(coord, "="); i >= 0 {
			coord = coord[:i]
		}
		if coord == "empty" {
			continue
		}
		parts := strings.Split(coord, ":")
		if len(parts) != 3 {
			continue
		}
		group, artifact, version := parts[0], parts[1], parts[2]
		if group == "" || artifact == "" {
			continue
		}
		name := group + ":" + artifact
		key := name + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		s.emit(base, name, version, projectPath, path, "maven-gradle-lockfile", "gradle", "high")
	}
	return sc.Err()
}

type pom struct {
	XMLName      xml.Name `xml:"project"`
	Dependencies []pomDep `xml:"dependencies>dependency"`
	// Dependencies declared under dependencyManagement are version
	// policy for child modules, not dependencies of this module.
	Management struct {
		Dependencies []pomDep `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
}

type pomDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
}

// ScanPomXML parses the declared dependencies of a pom.xml. Everything
// here is low confidence: a pom states intent, and the version may be a
// property reference or inherited from a parent pom this scanner does
// not resolve.
func (s *Scanner) ScanPomXML(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var p pom
	if err := xml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse pom.xml: %w", err)
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	for _, d := range p.Dependencies {
		group := strings.TrimSpace(d.GroupID)
		artifact := strings.TrimSpace(d.ArtifactID)
		if group == "" || artifact == "" {
			continue
		}
		version := strings.TrimSpace(d.Version)
		// An unresolved property placeholder is not a version. Emitting
		// "${spring.version}" would be worse than emitting nothing: it
		// can never match a catalog and it looks like real data.
		if strings.Contains(version, "${") {
			version = ""
		}
		name := group + ":" + artifact
		key := name + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		r := base
		r.InstallScope = scopeOf(d.Scope)
		s.emitRecord(r, name, version, projectPath, path, "maven-pom-xml", "maven", "low")
	}
	return nil
}

func scopeOf(scope string) string {
	switch strings.TrimSpace(scope) {
	case "test", "provided":
		return "dev"
	case "":
		return ""
	default:
		return "prod"
	}
}

// IsLocalRepoPom returns (true, groupArtifact, version, versionDir) if
// path is the `.pom` at the root of a local Maven repository artifact:
//
//	~/.m2/repository/com/google/guava/guava/33.2.1-jre/guava-33.2.1-jre.pom
//
// Group is reconstructed from the directory path between `repository`
// and the artifact directory. The file is used only as a marker; its XML
// is not read, because the layout already carries the coordinates.
func IsLocalRepoPom(path string) (bool, string, string, string) {
	if !strings.HasSuffix(path, ".pom") {
		return false, "", "", ""
	}
	versionDir := filepath.Dir(path)
	version := filepath.Base(versionDir)
	artifactDir := filepath.Dir(versionDir)
	artifact := filepath.Base(artifactDir)
	if version == "" || artifact == "" || version == "." || artifact == "." {
		return false, "", "", ""
	}
	// The marker is <artifact>-<version>.pom at the version root.
	if filepath.Base(path) != artifact+"-"+version+".pom" {
		return false, "", "", ""
	}
	// Reconstruct the group from the path segments under "repository".
	segs := strings.Split(filepath.ToSlash(filepath.Dir(artifactDir)), "/")
	repoIdx := -1
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] == "repository" {
			repoIdx = i
			break
		}
	}
	if repoIdx < 0 || repoIdx+1 >= len(segs) {
		return false, "", "", ""
	}
	group := strings.Join(segs[repoIdx+1:], ".")
	if group == "" {
		return false, "", "", ""
	}
	return true, group + ":" + artifact, version, versionDir
}

// ScanLocalRepoArtifact emits a record for an artifact in the local
// Maven repository. Identity comes from the directory layout.
func (s *Scanner) ScanLocalRepoArtifact(path, name, version, versionDir string, base model.Record) error {
	s.emit(base, name, version, versionDir, path, "maven-local-repository", "maven", "high")
	return nil
}

func (s *Scanner) emit(base model.Record, name, version, projectPath, sourceFile, sourceType, manager, confidence string) {
	s.emitRecord(base, name, version, projectPath, sourceFile, sourceType, manager, confidence)
}

func (s *Scanner) emitRecord(base model.Record, name, version, projectPath, sourceFile, sourceType, manager, confidence string) {
	if version == "" && confidence != "low" {
		confidence = "low"
	}
	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = name
	// Maven coordinates are case-sensitive in practice but compared
	// case-insensitively by advisories; lowercase for matching only.
	r.NormalizedName = strings.ToLower(name)
	r.Version = version
	r.ProjectPath = projectPath
	r.PackageManager = manager
	r.SourceType = sourceType
	r.SourceFile = sourceFile
	r.Confidence = confidence
	s.Emit(r)
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
