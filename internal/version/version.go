package version

import (
	"fmt"
	"runtime"
)

// Version is overridden at build time via -ldflags "-X relay-download/internal/version.Version=...".
var Version = "dev"

func String(component string) string {
	return fmt.Sprintf("%s %s (%s/%s)", component, Version, runtime.GOOS, runtime.GOARCH)
}
