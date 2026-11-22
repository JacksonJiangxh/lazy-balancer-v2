//go:build linux

package services

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// HardenProcessMemoryForCerts applies the Go-side part of the certificate
// memory-protection baseline (JJC-20261122-003 P1-3, gap C):
//
//   - PR_SET_DUMPABLE=0: the kernel refuses core dumps for this process and
//     blocks ptrace reads of its memory by non-privileged peers, so the
//     transient plaintext cert/key bytes held during DB decryption cannot be
//     exfiltrated via a core file or /proc/<pid>/mem.
//
// It is defense-in-depth alongside the entrypoint's `ulimit -c 0`. Callers must
// treat failure as fatal when Route A (DB cert loader) is enabled: a process
// that cannot protect plaintext must not serve certs.
//
// Note: mlock/MADV_DONTDUMP on individual Go slices are deliberately not used —
// Go's moving/conservative GC and stack copies make per-allocation mlock
// unreliable, and the pinned-memory limit (RLIMIT_MEMLOCK) is tiny by default.
// The enforceable baseline is core-dump disable + swapoff/encrypted-swap at the
// container host, plus in-code zeroing (clearBytes) of DEK/plaintext buffers.
func HardenProcessMemoryForCerts() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_DUMPABLE=0: %w", err)
	}
	return nil
}
