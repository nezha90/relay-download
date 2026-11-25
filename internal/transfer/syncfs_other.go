//go:build !linux

package transfer

// SyncFS falls back to SyncDir on non-Linux platforms.
func SyncFS(dir string) error {
	return SyncDir(dir)
}
