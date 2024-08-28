package aead

import (
	"bytes"

	"github.com/mengzhuo/go-kcapi/internal"
	"golang.org/x/sys/unix"
)

const (
	gcmStandardNonceSize = 12
	gcmMinimumTagSize    = 12
	gcmTagSize           = 16
	gcmBlockSize         = 16
)

type handle struct {
	name      string
	addr      *unix.SockaddrALG
	opfd      uintptr
	nonceSize int
	tagSize   int
	keySize   int
	blockSize int
}

func newHandle(name string, key []byte, nonceSize int, tagSize int, blockSize int) (*handle, error) {
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

	h := &handle{
		name:      name,
		addr:      addr,
		opfd:      opfd,
		nonceSize: nonceSize,
		tagSize:   tagSize,
		keySize:   len(key),
		blockSize: blockSize,
	}

	return h, nil
}

type GCM struct {
	handle
}

func newGCM(name string, key []byte, nonceSize int, tagSize int) (*GCM, error) {
	h, err := newHandle(name, key, nonceSize, tagSize, gcmBlockSize)
	return &GCM{*h}, err
}

func (g *GCM) Seal(dst, nonce, plaintext, data []byte) (r []byte) {

	if len(nonce) != g.nonceSize {
		panic("nonce size not matched")
	}

	oob := bytes.NewBuffer(internal.CipherOperation(unix.ALG_OP_ENCRYPT))
	oob.Write(internal.CipherIV(nonce))
	oob.Write(internal.CipherAEADAssocLen(len(data)))

	pbuf := bytes.NewBuffer(nil)
	if len(data) > 0 {
		pbuf.Write(data)
	}
	pbuf.Write(plaintext)

	err := unix.Sendmsg(int(g.opfd),
		pbuf.Bytes(),
		oob.Bytes(),
		g.addr, 0)

	if err != nil {
		panic(err)
	}

	if len(dst) >= g.tagSize+g.blockSize {
		r = dst
	} else {
		r = make([]byte, g.tagSize+g.blockSize)
	}

	_, err = unix.Read(int(g.opfd), r)
	if err != nil {
		panic(err)
	}
	return
}

func (g *GCM) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	return nil, nil
}
