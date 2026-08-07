package safeopen

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRegularOpensRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, info, err := Regular(path)
	if err != nil {
		t.Fatalf("Regular: %v", err)
	}
	defer f.Close()
	if info.Size() != 2 {
		t.Fatalf("size = %d, want 2", info.Size())
	}
}

// A symlink whose target is an ordinary readable file is the exploit the
// mode check alone does not catch: os.Open follows it and f.Stat() reports
// the target's regular mode.
func TestRegularRejectsSymlinkToRegularFile(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "credentials")
	if err := os.WriteFile(secret, []byte("token=hunter2"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "poetry.lock")
	if err := os.Symlink(secret, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires privilege on Windows")
		}
		t.Fatal(err)
	}
	f, _, err := Regular(link)
	if err == nil {
		f.Close()
		t.Fatal("Regular followed a symlink to a regular file")
	}
	if !errors.Is(err, ErrSymlink) {
		t.Fatalf("err = %v, want ErrSymlink", err)
	}
}

func TestRegularRejectsSymlinkToDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sub")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "uv.lock")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires privilege on Windows")
		}
		t.Fatal(err)
	}
	f, _, err := Regular(link)
	if err == nil {
		f.Close()
		t.Fatal("Regular followed a symlink to a directory")
	}
}

func TestRegularRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	f, _, err := Regular(dir)
	if err == nil {
		f.Close()
		t.Fatal("Regular accepted a directory")
	}
}

func TestRegularRejectsFIFO(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "Cargo.lock")
	if err := mkfifo(path); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	f, _, err := Regular(path)
	if err == nil {
		f.Close()
		t.Fatal("Regular accepted a FIFO")
	}
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestRegularMissingFile(t *testing.T) {
	f, _, err := Regular(filepath.Join(t.TempDir(), "absent.lock"))
	if err == nil {
		f.Close()
		t.Fatal("Regular accepted a missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
}
