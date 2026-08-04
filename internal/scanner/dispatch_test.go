package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/output"
)

// The walker's `switch` and the worker's `switch j.kind` are linked only
// by matching magic strings, so a typo in either compiles cleanly and
// silently drops an entire ecosystem. This test walks a tree containing
// one fixture per newly supported source and asserts every one of them
// produces a record, which is the only thing that catches that class of
// mistake.
func TestDispatchCoversEveryEcosystem(t *testing.T) {
	root := t.TempDir()

	// NuGet — all four shapes.
	writeFile(t, filepath.Join(root, "dotnet", "packages.lock.json"), `{
  "version": 1,
  "dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}}}
}`)
	writeFile(t, filepath.Join(root, "dotnet", "packages.config"),
		`<packages><package id="EntityFramework" version="6.4.4" /></packages>`)
	writeFile(t, filepath.Join(root, "dotnet", "App.deps.json"),
		`{"libraries": {"Serilog/3.1.1": {"type": "package"}}}`)
	writeFile(t, filepath.Join(root, "dotnet", "Directory.Packages.props"),
		`<Project><ItemGroup><PackageVersion Include="Polly" Version="8.2.0" /></ItemGroup></Project>`)

	// Cargo.
	writeFile(t, filepath.Join(root, "rust", "Cargo.lock"), `
[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)

	// Java — pom, gradle lock, sbt lock.
	writeFile(t, filepath.Join(root, "java", "pom.xml"), `<project>
  <dependencies><dependency>
    <groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.14.0</version>
  </dependency></dependencies>
</project>`)
	writeFile(t, filepath.Join(root, "java", "gradle.lockfile"),
		"com.google.guava:guava:32.1.3-jre=runtimeClasspath\n")
	writeFile(t, filepath.Join(root, "java", "build.sbt.lock"),
		`{"dependencies": [{"org": "org.typelevel", "name": "cats-core", "version": "2.10.0"}]}`)

	// Swift PM and CocoaPods.
	writeFile(t, filepath.Join(root, "ios", "Package.resolved"), `{
  "pins": [{"identity": "alamofire", "location": "https://github.com/Alamofire/Alamofire.git",
            "state": {"revision": "abc", "version": "5.8.1"}}],
  "version": 2
}`)
	writeFile(t, filepath.Join(root, "ios", "Podfile.lock"), "PODS:\n  - SnapKit (5.6.0)\n")

	// Dart, Elixir, Conan, Julia.
	writeFile(t, filepath.Join(root, "dart", "pubspec.lock"), `packages:
  http:
    dependency: "direct main"
    source: hosted
    version: "1.1.2"
`)
	writeFile(t, filepath.Join(root, "elixir", "mix.lock"),
		`%{"jason": {:hex, :jason, "1.4.1", "aaa", [:mix], [], "hexpm", "bbb"},}`)
	writeFile(t, filepath.Join(root, "cpp", "conan.lock"),
		`{"version": "0.5", "requires": ["zlib/1.2.13"]}`)
	writeFile(t, filepath.Join(root, "jl", "Manifest.toml"), `manifest_format = "2.0"

[[deps.JSON]]
uuid = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
version = "0.21.4"
`)

	// Python declaration/lock formats.
	writeFile(t, filepath.Join(root, "py", "requirements.txt"), "requests==2.31.0\n")
	writeFile(t, filepath.Join(root, "py", "Pipfile.lock"),
		`{"default": {"urllib3": {"version": "==2.1.0"}}}`)
	writeFile(t, filepath.Join(root, "py", "poetry.lock"), "[[package]]\nname = \"click\"\nversion = \"8.1.7\"\n")
	writeFile(t, filepath.Join(root, "py", "uv.lock"), "[[package]]\nname = \"attrs\"\nversion = \"23.2.0\"\n")
	writeFile(t, filepath.Join(root, "py", "pylock.toml"), "[[packages]]\nname = \"idna\"\nversion = \"3.6\"\n")

	// Go workspace and vendor manifests.
	writeFile(t, filepath.Join(root, "gowork", "go.work.sum"),
		"github.com/google/uuid v1.5.0 h1:abc=\n")
	writeFile(t, filepath.Join(root, "goproj", "vendor", "modules.txt"),
		"# github.com/pkg/errors v0.9.1\n## explicit\ngithub.com/pkg/errors\n")

	// Codex MCP config (TOML).
	writeFile(t, filepath.Join(root, ".codex", "config.toml"),
		"[mcp_servers.pw]\ncommand = \"npx\"\nargs = [\"-y\", \"@playwright/mcp@latest\"]\n")

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	em := output.New(stdout, stderr, "dispatchtest")

	if _, err := Run(context.Background(), Config{
		Roots:       []Root{{Path: root, Kind: model.RootKindProject}},
		Profile:     model.ProfileProject,
		MaxFileSize: 5 * 1024 * 1024,
		Concurrency: 2,
		BaseRecord: model.Record{
			SchemaVersion:  model.SchemaVersion,
			ScannerName:    model.ScannerName,
			ScannerVersion: "test",
			RunID:          "dispatchtest",
			ScanTime:       time.Now().UTC().Format(time.RFC3339Nano),
		},
		Emitter: em,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	sourceTypes := map[string]bool{}
	ecosystems := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r model.Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("bad ndjson line: %v: %s", err, line)
		}
		if r.RecordType != model.RecordTypePackage {
			continue
		}
		sourceTypes[r.SourceType] = true
		ecosystems[r.Ecosystem] = true
	}

	wantSourceTypes := []string{
		"nuget-packages-lock", "nuget-packages-config", "nuget-deps-json", "nuget-packages-props",
		"cargo-lock",
		"maven-pom", "gradle-lockfile", "sbt-lock",
		"swift-package-resolved", "cocoapods-podfile-lock",
		"pub-lock", "hex-mix-lock", "conan-lock", "julia-manifest",
		"pip-requirements", "pipenv-lock", "poetry-lock", "uv-lock", "pylock",
		"go-work-sum", "go-vendor-modules",
		"mcp-config",
	}
	for _, want := range wantSourceTypes {
		if !sourceTypes[want] {
			t.Errorf("no record with source_type %q — dispatch wiring is broken for it", want)
		}
	}

	wantEcosystems := []string{
		model.EcosystemNuGet, model.EcosystemCratesIO, model.EcosystemMaven,
		model.EcosystemSwift, model.EcosystemCocoaPods, model.EcosystemPub,
		model.EcosystemHex, model.EcosystemConan, model.EcosystemJulia,
		model.EcosystemPyPI, model.EcosystemGo, model.EcosystemMCP,
	}
	for _, want := range wantEcosystems {
		if !ecosystems[want] {
			t.Errorf("no record for ecosystem %q", want)
		}
	}
}

// Every emitted ecosystem must be selectable via --ecosystem, which reads
// the same registry. A constant added to one collection but not the other
// fails silently at runtime.
func TestAllEmittedEcosystemsAreSupported(t *testing.T) {
	for _, ecosystem := range model.SupportedEcosystems() {
		if !model.IsSupportedEcosystem(ecosystem) {
			t.Errorf("ecosystem %q is in the order list but not the support map", ecosystem)
		}
	}
	// Guard the reverse direction for the ecosystems added here.
	for _, ecosystem := range []string{
		model.EcosystemNuGet, model.EcosystemCratesIO, model.EcosystemMaven,
		model.EcosystemSwift, model.EcosystemCocoaPods, model.EcosystemPub,
		model.EcosystemHex, model.EcosystemConan, model.EcosystemJulia,
	} {
		if !model.IsSupportedEcosystem(ecosystem) {
			t.Errorf("ecosystem %q is not registered as supported", ecosystem)
		}
		found := false
		for _, listed := range model.SupportedEcosystems() {
			if listed == ecosystem {
				found = true
			}
		}
		if !found {
			t.Errorf("ecosystem %q missing from SupportedEcosystems()", ecosystem)
		}
	}
}

// Three sources are gated on file *shape* rather than a plain basename:
// a cached .nuspec must sit in <id>/<version>/, a Java archive must be a
// readable zip carrying Maven coordinates, and a Go binary must be an
// executable in a bin/ directory. They are exercised separately because
// building the fixtures is more involved than writing a text file.
func TestDispatchCoversShapeGatedSources(t *testing.T) {
	root := t.TempDir()

	// NuGet global-cache layout.
	writeFile(t, filepath.Join(root, "nugetcache", "serilog", "3.1.1", "serilog.nuspec"),
		`<package><metadata><id>Serilog</id><version>3.1.1</version></metadata></package>`)

	// A jar carrying embedded Maven coordinates.
	jarPath := filepath.Join(root, "libs", "guava.jar")
	if err := os.MkdirAll(filepath.Dir(jarPath), 0o755); err != nil {
		t.Fatal(err)
	}
	jf, err := os.Create(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(jf)
	w, err := zw.Create("META-INF/maven/com.google.guava/guava/pom.properties")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("groupId=com.google.guava\nartifactId=guava\nversion=32.1.3-jre\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	jf.Close()

	// A real Go binary in a bin/ directory: copy this test binary, which
	// carries genuine build info.
	//
	// No go-binary record can be asserted here. This module has zero
	// non-stdlib dependencies, so a binary built from it reports
	// len(Deps)==0, and its own Main.Version is "(devel)", which
	// ScanGoBinary deliberately skips as a local build with no release
	// version. The fixture is still worth walking: it exercises the
	// candidate predicate and the buildinfo read end to end, so a panic
	// or a hard error on a real binary would fail the test. Record-level
	// coverage lives in gomod's binary_test.go, and the dispatch wiring
	// itself is now compile-checked through the kind constants.
	if runtime.GOOS != "windows" {
		if exe, err := os.Executable(); err == nil {
			if data, err := os.ReadFile(exe); err == nil {
				binPath := filepath.Join(root, "bin", "mytool")
				if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(binPath, data, 0o755); err != nil {
					t.Fatal(err)
				}
			}
		}
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	em := output.New(stdout, stderr, "shapetest")

	if _, err := Run(context.Background(), Config{
		Roots:       []Root{{Path: root, Kind: model.RootKindProject}},
		Profile:     model.ProfileProject,
		MaxFileSize: 200 * 1024 * 1024,
		Concurrency: 2,
		BaseRecord: model.Record{
			SchemaVersion:  model.SchemaVersion,
			ScannerName:    model.ScannerName,
			ScannerVersion: "test",
			RunID:          "shapetest",
			ScanTime:       time.Now().UTC().Format(time.RFC3339Nano),
		},
		Emitter: em,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	sourceTypes := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r model.Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("bad ndjson line: %v: %s", err, line)
		}
		if r.RecordType == model.RecordTypePackage {
			sourceTypes[r.SourceType] = true
		}
	}

	for _, want := range []string{"nuget-nuspec", "maven-archive"} {
		if !sourceTypes[want] {
			t.Errorf("no record with source_type %q — dispatch wiring is broken for it", want)
		}
	}
}
