package aead

import (
	"golang.org/x/sys/unix"
)

type Handle struct {
	Name      string
	Addr      *unix.SockaddrALG
	Opfd      uintptr
	NonceSize int
	TagSize   int
	KeySize   int
	BlockSize int
}

func NewHandle(name string, key []byte, nonceSize int, tagSize int, blockSize int) (*Handle, error) {
	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrALG{Type: "aead", Name: name}
	err = unix.Bind(fd, addr)
	if err != nil {
		return nil, err
	}

	err = unix.SetsockoptString(fd, unix.SOL_ALG, unix.ALG_SET_KEY, string(key))
	if err != nil {
		return nil, err
	}

	_, _, e1 := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd),
		unix.SOL_ALG, unix.ALG_SET_AEAD_AUTHSIZE, 0,
		uintptr(tagSize), 0)
	if e1 != 0 {
		return nil, unix.Errno(e1)
	}

	opfd, _, eno := unix.Syscall(unix.SYS_ACCEPT, uintptr(fd), 0, 0)
	if eno != 0 {
		return nil, unix.Errno(eno)
	}

	h := &Handle{
		Name:      name,
		Addr:      addr,
		Opfd:      opfd,
		NonceSize: nonceSize,
		TagSize:   tagSize,
		KeySize:   len(key),
		BlockSize: blockSize,
	}

	return h, nil
}
