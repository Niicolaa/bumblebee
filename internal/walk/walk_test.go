package walk

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestDefaultExcludesCoverProtectedMacOSLibraryPaths ensures the macOS
// Library subtrees that routinely produce TCC denials under broad
// $HOME scans are matched by the default suffix-component excludes.
// Adding new paths to DefaultExcludes is cheap; regressing one of
// these silently is what makes the diagnostics output scary.
func TestDefaultExcludesCoverProtectedMacOSLibraryPaths(t *testing.T) {
	want := []string{
		"Library/ContainerManager",
		"Library/Daemon Containers",
		"Library/DoNotDisturb",
		"Library/DuetExpertCenter",
		"Library/IntelligencePlatform",
		"Library/Photos",
		"Library/Sharing",
		"Library/Shortcuts",
		"Library/StatusKit",
	}
	have := make(map[string]bool, len(DefaultExcludes))
	for _, x := range DefaultExcludes {
		have[x] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("DefaultExcludes missing %q", w)
		}
	}
}

// TestWalkSkipsExcludedLibrarySubtrees verifies that an exclude with
// a "/"-separated suffix (e.g. "Library/ContainerManager") prunes a
// matching directory anywhere under any root, while a sibling
// directory that does not match continues to be walked.
func TestWalkSkipsExcludedLibrarySubtrees(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path-separator semantics differ on Windows")
	}
	root := t.TempDir()
	// Simulate a $HOME-shaped tree.
	mustMkdir(t, filepath.Join(root, "Library", "ContainerManager", "deep"))
	mustMkdir(t, filepath.Join(root, "Library", "StatusKit"))
	mustMkdir(t, filepath.Join(root, "code", "proj"))

	// Drop sentinel files we can detect from the visitor.
	mustWrite(t, filepath.Join(root, "Library", "ContainerManager", "deep", "secret.json"), "{}")
	mustWrite(t, filepath.Join(root, "Library", "StatusKit", "x"), "{}")
	mustWrite(t, filepath.Join(root, "code", "proj", "package-lock.json"), "{}")

	excludes := append([]string{}, DefaultExcludes...)

	var seen []string
	err := Walk(Options{
		Roots:    []string{root},
		Excludes: excludes,
	}, func(path string, d fs.DirEntry) error {
		if !d.IsDir() {
			seen = append(seen, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, p := range seen {
		if filepath.Base(filepath.Dir(p)) == "deep" || filepath.Base(filepath.Dir(p)) == "StatusKit" {
			t.Errorf("excluded path was visited: %s", p)
		}
	}
	want := filepath.Join(root, "code", "proj", "package-lock.json")
	found := false
	for _, p := range seen {
		if p == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to visit %q; saw %v", want, seen)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mustSymlink creates a symlink, skipping the test where the platform
// denies symlink creation (unprivileged Windows without developer mode).
func mustSymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
}

// TestWalkSkipsDiscoveredFileSymlinks proves a symlinked *file* found
// below a root is never handed to a visitor: parsers dereference what
// they are given, so surfacing one would let a planted link redirect a
// read to a file outside the scanned tree.
func TestWalkSkipsDiscoveredFileSymlinks(t *testing.T) {
	tmp := t.TempDir()
	outside := filepath.Join(tmp, "outside")
	mustMkdir(t, outside)
	secret := filepath.Join(outside, "secret.json")
	mustWrite(t, secret, `{"secret":true}`)

	root := filepath.Join(tmp, "root")
	mustMkdir(t, root)
	real := filepath.Join(root, "package-lock.json")
	mustWrite(t, real, `{}`)
	link := filepath.Join(root, "linked-lock.json")
	mustSymlink(t, secret, link)

	var seen []string
	if err := Walk(Options{Roots: []string{root}}, func(p string, d fs.DirEntry) error {
		seen = append(seen, p)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, p := range seen {
		if p == link {
			t.Errorf("file symlink was visited: %s", p)
		}
	}
	found := false
	for _, p := range seen {
		if p == real {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to visit %q; saw %v", real, seen)
	}
}

// TestWalkVisitsSymlinkedFileRoot pins the root exemption: a handful of
// roots (e.g. ~/.claude.json) are single config files, and dotfile
// managers commonly symlink them. The root path is operator-supplied,
// so it is still visited.
func TestWalkVisitsSymlinkedFileRoot(t *testing.T) {
	tmp := t.TempDir()
	store := filepath.Join(tmp, "dotfiles")
	mustMkdir(t, store)
	target := filepath.Join(store, "claude.json")
	mustWrite(t, target, `{"mcpServers":{}}`)

	home := filepath.Join(tmp, "home")
	mustMkdir(t, home)
	root := filepath.Join(home, ".claude.json")
	mustSymlink(t, target, root)

	var seen []string
	if err := Walk(Options{Roots: []string{root}}, func(p string, d fs.DirEntry) error {
		seen = append(seen, p)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != root {
		t.Errorf("expected symlinked file root %q to be visited; saw %v", root, seen)
	}
}
