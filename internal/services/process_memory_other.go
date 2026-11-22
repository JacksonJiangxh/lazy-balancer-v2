//go:build !linux

package services

// HardenProcessMemoryForCerts is a no-op off Linux. The certificate DB loader
// is deployed in the Linux container where PR_SET_DUMPABLE / ulimit -c apply;
// developer machines (Windows/macOS) keep their normal process semantics.
func HardenProcessMemoryForCerts() error { return nil }
