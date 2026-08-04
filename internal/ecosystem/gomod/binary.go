package gomod

import (
	"debug/buildinfo"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

// Go binaries carry their own module graph.
//
// `go install` writes compiled tools into ~/go/bin, and nothing else on
// disk records what went into them: there is no lockfile, no manifest,
// and the module cache does not say which versions a given tool was built
// from. Since Go 1.18 the standard library can read the build info
// embedded in the binary itself, so a compromised CLI tool installed via
// `go install` is detectable with no third-party dependency.
//
// Detection is deliberately narrow. Probing every regular file on a
// developer machine would be wasteful, so a candidate must live in a
// directory named `bin` and be executable (or carry a Windows executable
// extension). ~/go/bin is already a curated baseline root, which is the
// case this targets.

// maxGoBinarySize bounds which executables are probed. The Scanner's
// MaxFileSize governs metadata text files that are read end to end;
// buildinfo seeks directly to the embedded build-info section rather than
// reading the whole file, so applying that much smaller bound here would
// skip essentially every real binary.
const maxGoBinarySize = 512 << 20 // 512 MiB

// IsGoBinaryCandidate reports whether an entry is worth probing for Go
// build info. It never opens the file.
func IsGoBinaryCandidate(path string, d fs.DirEntry) bool {
	if d == nil || d.IsDir() {
		return false
	}
	if filepath.Base(filepath.Dir(path)) != "bin" {
		return false
	}
	base := filepath.Base(path)
	if runtime.GOOS == "windows" {
		switch strings.ToLower(filepath.Ext(base)) {
		case ".exe", ".com":
			return true
		}
		return false
	}
	// A dotted extension on Unix (.sh, .py, .dylib) means a script or
	// library rather than a compiled command.
	if filepath.Ext(base) != "" {
		return false
	}
	info, err := d.Info()
	if err != nil {
		return false
	}
	if !info.Mode().IsRegular() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

// ScanGoBinary reads the module graph embedded in a Go binary. Files that
// are not Go binaries fail fast inside buildinfo and are skipped silently:
// on a populated bin directory most candidates are expected to be
// something else, so a diagnostic per miss would be pure noise.
func (s *Scanner) ScanGoBinary(path string, base model.Record) error {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	if info.Size() > maxGoBinarySize {
		if s.Diag != nil {
			s.Diag("debug", path, fmt.Sprintf("skipping binary: size %d exceeds %d", info.Size(), int64(maxGoBinarySize)))
		}
		return nil
	}
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil
	}
	projectPath := filepath.Dir(path)
	seen := make(map[string]struct{})

	emit := func(module, version string, main bool) {
		if module == "" || version == "" {
			return
		}
		// A binary built from a local checkout reports "(devel)" — real
		// identity, but no release version to match a catalog against.
		if version == "(devel)" {
			return
		}
		key := module + "\x00" + version
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}

		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = module
		r.NormalizedName = strings.ToLower(module)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "go"
		r.SourceType = "go-binary"
		r.SourceFile = path
		if main {
			direct := true
			r.DirectDependency = &direct
		} else {
			direct := false
			r.DirectDependency = &direct
			r.InstallScope = "indirect"
		}
		r.Confidence = "high"
		s.Emit(r)
	}

	emit(bi.Main.Path, bi.Main.Version, true)
	for _, dep := range bi.Deps {
		if dep == nil {
			continue
		}
		// A replaced module reports the replacement's coordinates.
		if dep.Replace != nil {
			emit(dep.Replace.Path, dep.Replace.Version, false)
			continue
		}
		emit(dep.Path, dep.Version, false)
	}
	return nil
}
