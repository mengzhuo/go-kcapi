package internal

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// XXX: There are two unexported methods that we need

// Copied from golang.org/x/sys/unix
func cmsgAlignOf(salen int) int {
	salign := unix.SizeofPtr

	// dragonfly needs to check ABI version at runtime, see cmsgAlignOf in
	// sockcmsg_dragonfly.go
	switch runtime.GOOS {
	case "aix":
		// There is no alignment on AIX.
		salign = 1
	case "darwin", "ios", "illumos", "solaris":
		// NOTE: It seems like 64-bit Darwin, Illumos and Solaris
		// kernels still require 32-bit aligned access to network
		// subsystem.
		if unix.SizeofPtr == 8 {
			salign = 4
		}
	case "netbsd", "openbsd":
		// NetBSD and OpenBSD armv7 require 64-bit alignment.
		if runtime.GOARCH == "arm" {
			salign = 8
		}
		// NetBSD aarch64 requires 128-bit alignment.
		if runtime.GOOS == "netbsd" && runtime.GOARCH == "arm64" {
			salign = 16
		}
	case "zos":
		// z/OS socket macros use [32-bit] sizeof(int) alignment,
		// not pointer width.
		salign = unix.SizeofInt
	}

	return (salen + salign - 1) & ^(salign - 1)
}

// Copied from golang.org/x/sys/unix
func Cmsgdata(h *unix.Cmsghdr, offset uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(h)) +
		uintptr(cmsgAlignOf(unix.SizeofCmsghdr)) + offset)
}
