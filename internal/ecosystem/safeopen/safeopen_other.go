//go:build !unix

package safeopen

import (
	"fmt"
	"os"
)

// openNoFollow rejects a symbolic link with a pre-open Lstat. O_NOFOLLOW
// has no portable equivalent here (syscall.O_NOFOLLOW is not defined on
// Windows), so this check is racy in principle; it still closes the
// symlinked-file read for the walk-discovered paths this package serves.
func openNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s: %w", path, ErrSymlink)
	}
	return os.Open(path)
}
