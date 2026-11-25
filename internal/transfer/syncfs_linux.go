//go:build linux

package transfer

import (
	"os"

	"golang.org/x/sys/unix"
)

// SyncFS flushes all dirty file data, inodes, and directory renames on the filesystem
// containing dir to durable storage in a single kernel commit barrier.
func SyncFS(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = unix.Syncfs(int(d.Fd()))
	_ = d.Close()
	return err
}
