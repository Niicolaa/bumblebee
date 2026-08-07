//go:build unix

package safeopen

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openNoFollow opens path with O_NOFOLLOW so the kernel rejects a symlink
// at the final path element atomically, with no window between check and
// open. O_NONBLOCK keeps the open from hanging on a FIFO with no writer;
// the caller's regular-file check rejects it immediately afterwards.
func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		// ELOOP is what most systems report for O_NOFOLLOW on a symlink;
		// NetBSD reports EFTYPE and some BSDs EMLINK.
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return nil, fmt.Errorf("%s: %w", path, ErrSymlink)
		}
		return nil, err
	}
	return f, nil
}
