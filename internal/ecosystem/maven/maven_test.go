package maven

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func run(t *testing.T, name, body string, fn func(*Scanner, string, model.Record) error) []model.Record {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := fn(s, path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	return out
}

func TestScanGradleLockfile(t *testing.T) {
	body := `# This is a Gradle generated file for dependency locking.
com.google.guava:guava:33.2.1-jre=compileClasspath,runtimeClasspath
org.apache.logging.log4j:log4j-core:2.17.1=runtimeClasspath
empty=annotationProcessor
`
	out := run(t, "gradle.lockfile", body, (*Scanner).ScanGradleLockfile)
	if len(out) != 2 {
		t.Fatalf("want 2 records, got %d: %+v", len(out), out)
	}
	if out[0].PackageName != "com.google.guava:guava" || out[0].Version != "33.2.1-jre" {
		t.Errorf("guava: %+v", out[0])
	}
	if out[0].Confidence != "high" {
		t.Errorf("a Gradle lock is fully resolved: %+v", out[0])
	}
	if out[1].PackageName != "org.apache.logging.log4j:log4j-core" {
		t.Errorf("log4j: %+v", out[1])
	}
}

// A pom declares intent, not resolution. Property placeholders must not
// be emitted as if they were versions.
func TestScanPomXML(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`
	out := run(t, "pom.xml", body, (*Scanner).ScanPomXML)
	if len(out) != 3 {
		t.Fatalf("want 3 records, got %d: %+v", len(out), out)
	}
	byName := map[string]model.Record{}
	for _, r := range out {
		byName[r.PackageName] = r
	}
	if got := byName["org.apache.logging.log4j:log4j-core"]; got.Version != "2.14.1" || got.Confidence != "low" {
		t.Errorf("log4j: %+v", got)
	}
	if got := byName["org.springframework:spring-core"]; got.Version != "" {
		t.Errorf("unresolved property must not become a version: %+v", got)
	}
	if got := byName["junit:junit"]; got.InstallScope != "dev" {
		t.Errorf("test scope: %+v", got)
	}
}

func TestIsLocalRepoPom(t *testing.T) {
	repo := filepath.Join("home", ".m2", "repository")
	cases := []struct {
		in      string
		ok      bool
		name    string
		version string
	}{
		{
			filepath.Join(repo, "com", "google", "guava", "guava", "33.2.1-jre", "guava-33.2.1-jre.pom"),
			true, "com.google.guava:guava", "33.2.1-jre",
		},
		{
			filepath.Join(repo, "junit", "junit", "4.13.2", "junit-4.13.2.pom"),
			true, "junit:junit", "4.13.2",
		},
		// Not the marker file for its own directory.
		{filepath.Join(repo, "junit", "junit", "4.13.2", "other-1.0.pom"), false, "", ""},
		{filepath.Join("home", "proj", "pom.xml"), false, "", ""},
	}
	for _, c := range cases {
		ok, name, version, _ := IsLocalRepoPom(c.in)
		if ok != c.ok || name != c.name || version != c.version {
			t.Errorf("IsLocalRepoPom(%q) = (%v, %q, %q), want (%v, %q, %q)",
				c.in, ok, name, version, c.ok, c.name, c.version)
		}
	}
}

func TestIsGradleLockfile(t *testing.T) {
	for in, want := range map[string]bool{
		"gradle.lockfile":     true,
		"app.gradle.lockfile": true,
		"build.gradle":        false,
		"settings.gradle.kts": false,
	} {
		if got := IsGradleLockfile(in); got != want {
			t.Errorf("IsGradleLockfile(%q) = %v, want %v", in, got, want)
		}
	}
}
