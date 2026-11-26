package agentb

import (
	"relay-download/internal/protocol"
	"relay-download/internal/transfer"
)

func IsSafeStorageDir(raw string) bool {
	return transfer.IsSafeStorageDir(raw)
}

func DiscoverHostDisks() []protocol.HostDisk {
	return transfer.DiscoverHostDisks("relay-delivery")
}
