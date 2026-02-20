//go:build windows

package txmetacache

import (
	"fmt"
	"sync/atomic"
)

// globalChunkCounter tracks the total number of mmap allocations across all buckets
var globalChunkCounter atomic.Uint64

// allocateNamedMmap is not supported on Windows
func allocateNamedMmap(size int) ([]byte, error) {
	return nil, fmt.Errorf("mmap allocation not supported on Windows")
}
