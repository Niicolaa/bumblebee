//go:build !unix

package safeopen

import "errors"

func mkfifo(string) error { return errors.New("mkfifo unsupported") }
