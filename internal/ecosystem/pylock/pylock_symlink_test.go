package pylock

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

// A poetry.lock that is really a symlink to an unrelated readable file must
// not be opened: its contents would otherwise reach the emitted records.
func TestScanPoetryLockRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.toml")
	if err := os.WriteFile(secret, []byte("[[package]]\nname = \"leaked\"\nversion = \"1.0\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "poetry.lock")
	if err := os.Symlink(secret, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires privilege on Windows")
		}
		t.Fatal(err)
	}
	var got []model.Record
	s := &Scanner{Emit: func(r model.Record) { got = append(got, r) }}
	if err := s.ScanPoetryLock(link, model.Record{}); err == nil {
		t.Fatal("ScanPoetryLock followed a symlink")
	}
	if len(got) != 0 {
		t.Fatalf("emitted %d records from a symlinked lockfile", len(got))
	}
}
