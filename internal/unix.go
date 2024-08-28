package internal

import (
	"bytes"
	"encoding/binary"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

var PageSize = 4096

func init() {
	PageSize = os.Getpagesize()
}

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

func DataBuffers(p []byte, blockSize int) (buf [][]byte) {
	bc := len(p) / blockSize
	if bc == 0 {
		bc = 1
	}
	buf = make([][]byte, bc)
	for i := range buf {
		buf[i] = p[i*blockSize : min(i*blockSize+blockSize, len(p))]
	}
	return
}

func SendMsg(fd uintptr, msgs ...[]byte) error {

	buf := bytes.NewBuffer(nil)
	for _, msg := range msgs {
		buf.Write(msg)
	}

	msgh := &unix.Msghdr{
		Control: &buf.Bytes()[0],
	}
	msgh.SetControllen(buf.Len())

	_, _, errno := unix.Syscall(unix.SYS_SENDMSG, fd,
		uintptr(unsafe.Pointer(msgh)), 0)
	if errno != 0 {
		return unix.Errno(errno)
	}
	return nil
}

func CipherOperation(op int) []byte {
	const opSize = int(unsafe.Sizeof(int32(0)))
	opbuf := make([]byte, unix.CmsgSpace(opSize))

	h := (*unix.Cmsghdr)(unsafe.Pointer(&opbuf[0]))
	h.Level = unix.SOL_ALG
	h.Type = unix.ALG_SET_OP
	h.SetLen(unix.CmsgLen(opSize))
	*(*int32)(Cmsgdata(h, 0)) = int32(op)

	return opbuf
}

func CipherIV(iv []byte) []byte {

	ivbuf := make([]byte, unix.CmsgSpace(len(iv)+4))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&ivbuf[0]))
	h.Level = unix.SOL_ALG
	h.Type = unix.ALG_SET_IV
	h.SetLen(unix.CmsgLen(len(iv) + 4))
	data := unsafe.Slice((*byte)(Cmsgdata(h, 0)), len(iv)+4)
	binary.LittleEndian.PutUint32(data, uint32(len(iv)))
	copy(data[4:], iv)

	return ivbuf
}

func CipherAEADAssocLen(l int) []byte {
	const opSize = int(unsafe.Sizeof(uint32(0)))
	opbuf := make([]byte, unix.CmsgSpace(opSize))

	h := (*unix.Cmsghdr)(unsafe.Pointer(&opbuf[0]))
	h.Level = unix.SOL_ALG
	h.Type = unix.ALG_SET_AEAD_ASSOCLEN
	h.SetLen(unix.CmsgLen(opSize))
	*(*uint32)(Cmsgdata(h, 0)) = uint32(l)
	return opbuf
}
