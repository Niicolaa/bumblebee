package gomod

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

// dirEntryFor writes a file with the given mode and returns its path and
// the fs.DirEntry the walker would hand to the predicate.
func dirEntryFor(t *testing.T, dir, name string, mode os.FileMode) (string, fs.DirEntry) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("x"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == name {
			return path, e
		}
	}
	t.Fatalf("entry %q not found", name)
	return "", nil
}

func TestIsGoBinaryCandidateRequiresBinDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable-bit semantics differ on Windows")
	}
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	otherDir := filepath.Join(root, "lib")
	for _, d := range []string{binDir, otherDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Executable inside bin/ — the case this targets (~/go/bin).
	path, entry := dirEntryFor(t, binDir, "mytool", 0o755)
	if !IsGoBinaryCandidate(path, entry) {
		t.Error("executable in bin/ should be a candidate")
	}

	// Same file outside bin/ must not be probed.
	path, entry = dirEntryFor(t, otherDir, "mytool", 0o755)
	if IsGoBinaryCandidate(path, entry) {
		t.Error("executable outside bin/ must not be a candidate")
	}

	// Non-executable file in bin/.
	path, entry = dirEntryFor(t, binDir, "notes", 0o644)
	if IsGoBinaryCandidate(path, entry) {
		t.Error("non-executable file must not be a candidate")
	}

	// Scripts and libraries carry an extension.
	path, entry = dirEntryFor(t, binDir, "script.sh", 0o755)
	if IsGoBinaryCandidate(path, entry) {
		t.Error("extensioned file must not be a candidate on unix")
	}
}

func TestIsGoBinaryCandidateRejectsDirectories(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	sub := filepath.Join(binDir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(binDir)
	if err != nil {
		t.Fatal(err)
	}
	if IsGoBinaryCandidate(sub, entries[0]) {
		t.Error("a directory must not be a candidate")
	}
	if IsGoBinaryCandidate(sub, nil) {
		t.Error("a nil DirEntry must not panic or match")
	}
}

// A bin/ directory on a real machine is mostly not Go binaries, so the
// scanner has to fail fast and silently rather than emitting a diagnostic
// per miss.
func TestScanGoBinaryOnNonGoFileIsSilent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notgo")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var got []model.Record
	var diags int
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { got = append(got, r) },
		Diag:        func(level, path, msg string) { diags++ },
	}
	if err := s.ScanGoBinary(path, model.Record{}); err != nil {
		t.Fatalf("non-Go file should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("emitted %d records from a shell script", len(got))
	}
	if diags != 0 {
		t.Errorf("emitted %d diagnostics; misses must be silent", diags)
	}
}

func TestScanGoBinaryOnMissingFileIsSilent(t *testing.T) {
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(model.Record) {}}
	if err := s.ScanGoBinary(filepath.Join(t.TempDir(), "absent"), model.Record{}); err != nil {
		t.Errorf("missing file should not error: %v", err)
	}
}

// The test binary is itself a Go binary, so it exercises the real
// buildinfo path without needing to shell out to the toolchain.
func TestScanGoBinaryReadsRealBuildInfo(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate test binary: %v", err)
	}
	var got []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { got = append(got, r) }}
	if err := s.ScanGoBinary(exe, model.Record{}); err != nil {
		t.Fatalf("reading own build info failed: %v", err)
	}
	for _, r := range got {
		if r.Ecosystem != model.EcosystemGo {
			t.Errorf("ecosystem = %q", r.Ecosystem)
		}
		if r.SourceType != "go-binary" {
			t.Errorf("source type = %q", r.SourceType)
		}
		// "(devel)" is a local build with no release version to match.
		if r.Version == "(devel)" {
			t.Error("(devel) builds must not be emitted")
		}
		if r.Version == "" || r.PackageName == "" {
			t.Errorf("incomplete record: %+v", r)
		}
	}
}
