// Package maven scans Java/JVM dependency artifacts.
//
// Four shapes are recognised:
//
//   - *gradle.lockfile — Gradle dependency locking. Resolved exact
//     versions, one per line. High confidence.
//   - *.sbt.lock — sbt-dependency-lock output. Resolved exact versions.
//   - pom.xml — a Maven project descriptor. This is a declaration, not a
//     resolved graph: transitive dependencies are absent and versions may
//     be inherited or expressed as ranges. Records are medium confidence
//     and version properties are resolved only one level, against the
//     pom's own <properties> block.
//   - JAR/WAR/EAR archives — the only evidence of what is actually
//     present in a local repository cache (~/.m2, ~/.gradle). Identity is
//     read from the embedded META-INF/maven/*/pom.properties.
//
// Package names follow the ecosystem convention of "groupId:artifactId",
// which is also how advisory feeds identify Maven packages.
//
// No `mvn` or `gradle` commands are executed.
package maven

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
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

// maxArchiveEntry bounds how much of an embedded pom.properties we read.
// The real file is a few hundred bytes; anything larger is malformed or
// hostile and is not worth buffering.
const maxArchiveEntry = 64 * 1024

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsPomXML(base string) bool { return base == "pom.xml" }

// IsGradleLockfile matches Gradle's dependency lock files. Gradle writes
// `gradle.lockfile` by default but prefixes it per-configuration in some
// setups, hence the suffix match.
func IsGradleLockfile(base string) bool { return strings.HasSuffix(base, "gradle.lockfile") }

func IsSbtLock(base string) bool { return strings.HasSuffix(base, ".sbt.lock") }

// IsJavaArchive matches the archive types that can carry Maven coordinates.
func IsJavaArchive(base string) bool {
	switch strings.ToLower(filepath.Ext(base)) {
	case ".jar", ".war", ".ear", ".par":
		return true
	}
	return false
}

// --- Gradle ---------------------------------------------------------------

func (s *Scanner) ScanGradleLockfile(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: group:artifact:version=conf1,conf2
		// The sentinel line "empty=<configurations>" carries no package.
		coords, _, _ := strings.Cut(line, "=")
		parts := strings.Split(coords, ":")
		if len(parts) != 3 {
			continue
		}
		group, artifact, version := parts[0], parts[1], parts[2]
		if group == "" || artifact == "" || version == "" {
			continue
		}
		s.emitCoord(base, group, artifact, version, projectPath, path, "gradle", "gradle-lockfile", "high", nil)
	}
	return nil
}

// --- sbt ------------------------------------------------------------------

type sbtLockFile struct {
	Dependencies []struct {
		Organization string `json:"org"`
		Name         string `json:"name"`
		Version      string `json:"version"`
	} `json:"dependencies"`
}

func (s *Scanner) ScanSbtLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var lock sbtLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		s.note(path, "unparseable sbt lock: "+err.Error())
		return nil
	}
	projectPath := filepath.Dir(path)
	for _, dep := range lock.Dependencies {
		if dep.Organization == "" || dep.Name == "" || dep.Version == "" {
			continue
		}
		s.emitCoord(base, dep.Organization, dep.Name, dep.Version, projectPath, path, "sbt", "sbt-lock", "high", nil)
	}
	return nil
}

// --- pom.xml --------------------------------------------------------------

type pomProject struct {
	XMLName    xml.Name `xml:"project"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Version    string   `xml:"version"`
	Parent     struct {
		GroupID string `xml:"groupId"`
		Version string `xml:"version"`
	} `xml:"parent"`
	Properties struct {
		Entries []xmlProperty `xml:",any"`
	} `xml:"properties"`
	Dependencies struct {
		Dependency []pomDependency `xml:"dependency"`
	} `xml:"dependencies"`
	DependencyManagement struct {
		Dependencies struct {
			Dependency []pomDependency `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"dependencyManagement"`
}

type xmlProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
}

func (s *Scanner) ScanPomXML(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var pom pomProject
	if err := xml.Unmarshal(data, &pom); err != nil {
		s.note(path, "unparseable pom.xml: "+err.Error())
		return nil
	}
	projectPath := filepath.Dir(path)

	props := map[string]string{}
	for _, p := range pom.Properties.Entries {
		props[p.XMLName.Local] = strings.TrimSpace(p.Value)
	}
	// project.version / project.parent.version are the two built-in
	// references that appear in real poms often enough to be worth
	// resolving.
	selfVersion := pom.Version
	if selfVersion == "" {
		selfVersion = pom.Parent.Version
	}
	if selfVersion != "" {
		props["project.version"] = selfVersion
		props["project.parent.version"] = pom.Parent.Version
	}

	deps := append([]pomDependency{}, pom.Dependencies.Dependency...)
	deps = append(deps, pom.DependencyManagement.Dependencies.Dependency...)
	seen := make(map[string]struct{})
	for _, dep := range deps {
		group := resolveProperty(dep.GroupID, props)
		artifact := resolveProperty(dep.ArtifactID, props)
		version := resolveProperty(dep.Version, props)
		if group == "" || artifact == "" || version == "" {
			continue
		}
		// Unresolved properties and version ranges are not exact versions.
		if strings.ContainsAny(version, "${}[](),") {
			continue
		}
		key := group + ":" + artifact + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		scope := strings.TrimSpace(dep.Scope)
		s.emitCoord(base, group, artifact, version, projectPath, path, "maven", "maven-pom", "medium", func(r *model.Record) {
			if scope != "" && scope != "compile" {
				r.InstallScope = scope
			}
			direct := true
			r.DirectDependency = &direct
		})
	}
	return nil
}

// resolveProperty expands a single ${name} reference against the pom's own
// properties. Nested or inherited properties are not resolved — that would
// require reading the parent pom chain, which means network or repository
// access this scanner deliberately avoids.
func resolveProperty(value string, props map[string]string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "${") || !strings.HasSuffix(value, "}") {
		return value
	}
	key := strings.TrimSuffix(strings.TrimPrefix(value, "${"), "}")
	if resolved, ok := props[key]; ok && resolved != "" {
		return resolved
	}
	return value
}

// --- JAR/WAR/EAR ----------------------------------------------------------

// ScanJavaArchive reads Maven coordinates from an archive's embedded
// META-INF/maven/<groupId>/<artifactId>/pom.properties. Archives without
// that entry (shaded uber-jars, hand-built jars) yield no records rather
// than a guess derived from the filename.
func (s *Scanner) ScanJavaArchive(path string, base model.Record) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if s.MaxFileSize > 0 && info.Size() > s.MaxFileSize {
		// Large archives are common in build output; this is expected, not
		// an error worth warning about on every jar.
		if s.Diag != nil {
			s.Diag("debug", path, fmt.Sprintf("skipping archive: size %d exceeds max %d", info.Size(), s.MaxFileSize))
		}
		return nil
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		// Not every .jar on disk is a valid zip (partial downloads, LFS
		// pointers). Not worth failing the scan over.
		s.note(path, "unreadable java archive: "+err.Error())
		return nil
	}
	defer zr.Close()

	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})
	for _, f := range zr.File {
		name := f.Name
		if !strings.HasPrefix(name, "META-INF/maven/") || !strings.HasSuffix(name, "/pom.properties") {
			continue
		}
		group, artifact, version := readPomProperties(f)
		if group == "" || artifact == "" || version == "" {
			continue
		}
		key := group + ":" + artifact + "\x00" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		s.emitCoord(base, group, artifact, version, projectPath, path, "maven", "maven-archive", "high", nil)
	}
	return nil
}

func readPomProperties(f *zip.File) (group, artifact, version string) {
	if f.UncompressedSize64 > maxArchiveEntry {
		return "", "", ""
	}
	rc, err := f.Open()
	if err != nil {
		return "", "", ""
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxArchiveEntry))
	if err != nil {
		return "", "", ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "groupId":
			group = strings.TrimSpace(value)
		case "artifactId":
			artifact = strings.TrimSpace(value)
		case "version":
			version = strings.TrimSpace(value)
		}
	}
	return group, artifact, version
}

// --- shared ---------------------------------------------------------------

func (s *Scanner) emitCoord(base model.Record, group, artifact, version, projectPath, sourceFile, manager, sourceType, confidence string, adjust func(*model.Record)) {
	name := group + ":" + artifact
	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = name
	r.NormalizedName = strings.ToLower(name)
	r.Version = version
	r.ProjectPath = projectPath
	r.PackageManager = manager
	r.SourceType = sourceType
	r.SourceFile = sourceFile
	r.Confidence = confidence
	if adjust != nil {
		adjust(&r)
	}
	s.Emit(r)
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
