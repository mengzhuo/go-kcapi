// Copyright 2024 Meng Zhuo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package skcipher internal use for kcapi
package skcipher

import (
	"encoding/binary"
	"os"
	"unsafe"

	"github.com/mengzhuo/go-kcapi/internal"
	"golang.org/x/sys/unix"
)

type BlockMode struct {
	Block *Block
	Op    int // Decrypt/Encrypt
}

func (b *BlockMode) BlockSize() int {
	return b.Block.Size
}

func (b *BlockMode) CryptBlocks(dst, src []byte) {
	ml := min(len(dst), len(src))
	if ml%b.Block.Size != 0 || ml < b.Block.Size {
		panic("invalid data")
	}
	b.Block.f.Write(src[:ml])
	b.Block.f.Read(dst[:ml])
}

type Block struct {
	Name string
	Size int
	bfd  uintptr
	f    *os.File
	addr *unix.SockaddrALG
}

func NewBlock(name string, key []byte, bs int) (*Block, error) {
	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrALG{Type: "skcipher", Name: name}
	err = unix.Bind(fd, addr)
	if err != nil {
		return nil, err
	}

	err = unix.SetsockoptString(fd, unix.SOL_ALG, unix.ALG_SET_KEY, string(key))
	if err != nil {
		return nil, err
	}

	bfd, _, eno := unix.Syscall(unix.SYS_ACCEPT, uintptr(fd), 0, 0)
	if eno != 0 {
		return nil, unix.Errno(eno)
	}

	return &Block{
		Name: name,
		bfd:  bfd,
		f:    os.NewFile(bfd, name),
		addr: addr,
		Size: bs,
	}, nil
}

func NewBlockMode(blk *Block, iv []byte, op int) (b *BlockMode, err error) {
	b = &BlockMode{
		Block: blk,
		Op:    op,
	}
	// There are 2 control messages (OOB) we have to send to sock
	// 1. SET_OP whether is decrypt or encrypt
	// 2. IV itself
	const opSize = int(unsafe.Sizeof(int32(0)))
	opbuf := make([]byte, unix.CmsgSpace(opSize))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&opbuf[0]))
	h.Level = unix.SOL_ALG
	h.Type = unix.ALG_SET_OP
	h.SetLen(unix.CmsgLen(opSize))
	*(*int32)(internal.Cmsgdata(h, 0)) = int32(op)

	ivbuf := make([]byte, unix.CmsgSpace(len(iv)+4))
	h = (*unix.Cmsghdr)(unsafe.Pointer(&ivbuf[0]))
	h.Level = unix.SOL_ALG
	h.Type = unix.ALG_SET_IV
	h.SetLen(unix.CmsgLen(len(iv) + 4))
	data := unsafe.Slice((*byte)(internal.Cmsgdata(h, 0)), len(iv)+4)
	binary.LittleEndian.PutUint32(data, uint32(len(iv)))
	copy(data[4:], iv)

	oob := append(opbuf, ivbuf...)
	msg := &unix.Msghdr{
		Control: &oob[0],
	}
	msg.SetControllen(len(oob))

	_, _, errno := unix.Syscall(unix.SYS_SENDMSG, uintptr(blk.bfd),
		uintptr(unsafe.Pointer(msg)), 0)
	if errno != 0 {
		err = unix.Errno(errno)
	}
	return
}
