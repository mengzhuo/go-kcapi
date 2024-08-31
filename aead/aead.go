package aead

import (
	"github.com/mengzhuo/go-kcapi/internal"
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

	opfd, addr, err := internal.NewAlgSock(name, "aead",
		func(fd int) error {
			err := unix.SetsockoptString(fd, unix.SOL_ALG, unix.ALG_SET_KEY, string(key))
			if err != nil {
				return err
			}
			_, _, e1 := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd),
				unix.SOL_ALG, unix.ALG_SET_AEAD_AUTHSIZE, 0,
				uintptr(tagSize), 0)
			if e1 != 0 {
				return unix.Errno(e1)
			}
			return nil
		},
	)

	if err != nil {
		return nil, err
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
