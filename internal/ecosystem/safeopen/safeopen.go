// Package safeopen opens metadata files discovered by the filesystem walk.
//
// Paths handed to a parser come from an untrusted tree, so a file named
// like a lockfile or manifest may in fact be a symbolic link pointing at
// an unrelated file (a credential store, a key), or a non-regular special
// file (FIFO, device, socket). Opening either would pull content the
// scanner is not meant to inventory into the emitted records. Regular
// refuses both.
package safeopen

import (
	"errors"
	"fmt"
	"os"
)

// ErrSymlink is returned when the path itself is a symbolic link.
var ErrSymlink = errors.New("path is a symbolic link")

// ErrNotRegular is returned when the path is not a regular file.
var ErrNotRegular = errors.New("not a regular file")

// Regular opens path read-only, refusing to follow a symbolic link at the
// final path element and refusing anything that is not a regular file. The
// caller owns the returned file and must close it.
func Regular(path string) (*os.File, os.FileInfo, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	return f, info, nil
}
