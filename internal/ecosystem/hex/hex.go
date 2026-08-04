// Package hex scans Elixir `mix.lock` files.
//
// mix.lock is an Elixir map literal rather than a data format, but the
// entries this scanner cares about have a fixed shape:
//
//	"castore": {:hex, :castore, "1.0.5", "<inner-hash>", [:mix], [], "hexpm", "<outer-hash>"},
//
// Only `:hex` entries are recorded — they are the ones that name a
// registry release. `:git` and `:path` entries point at VCS or local code
// whose third field is a revision, not a version.
package hex

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

const Ecosystem = model.EcosystemHex

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsMixLock(base string) bool { return base == "mix.lock" }

func (s *Scanner) ScanMixLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.Contains(line, "{:hex,") {
			continue
		}
		quoted := quotedFields(line)
		// quoted[0] is the map key (package name), quoted[1] the version;
		// the hashes follow.
		if len(quoted) < 2 {
			continue
		}
		name, version := quoted[0], quoted[1]
		if name == "" || version == "" {
			continue
		}
		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = name
		r.NormalizedName = strings.ToLower(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = "mix"
		r.SourceType = "hex-mix-lock"
		r.SourceFile = path
		r.Confidence = "high"
		s.Emit(r)
	}
	return nil
}

// quotedFields returns the double-quoted substrings of a line, in order.
// Escaped quotes are not expected in a generated lock file, but a
// backslash still suppresses the terminator so a stray escape cannot
// desynchronise the rest of the line.
func quotedFields(line string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		switch {
		case c == '\\' && inQuote:
			escaped = true
		case c == '"':
			if inQuote {
				out = append(out, b.String())
				b.Reset()
			}
			inQuote = !inQuote
		case inQuote:
			b.WriteByte(c)
		}
	}
	return out
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
