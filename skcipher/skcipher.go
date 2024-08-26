// Copyright 2024 Meng Zhuo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package skcipher internal use for kcapi
package skcipher

import (
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

// CryptBlocks not safe to called concurrently
func (b *BlockMode) CryptBlocks(dst, src []byte) {
	ml := min(len(dst), len(src))
	if ml%b.Block.Size != 0 || ml < b.Block.Size {
		panic("invalid data")
	}

	err := unix.Sendto(int(b.Block.bfd), src[:ml], unix.MSG_MORE, b.Block.addr)
	if err != nil {
		panic(err)
	}
	_, _, err = unix.Recvfrom(int(b.Block.bfd), dst[:ml], 0)
	if err != nil {
		panic(err)
	}
}

type Block struct {
	Name string
	Size int
	bfd  uintptr
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
	return b, internal.SendMsg(blk.bfd, internal.CipherOperation(op), internal.CipherIV(iv))
}

func NewCBCEncrypter(name string, key []byte, iv []byte, bs int) (*BlockMode, error) {

	blk, err := NewBlock(name, key, bs)
	if err != nil {
		return nil, err
	}

	return NewBlockMode(blk, iv, unix.ALG_OP_ENCRYPT)
}

func NewCBCDecrypter(name string, key []byte, iv []byte, bs int) (*BlockMode, error) {
	blk, err := NewBlock(name, key, bs)
	if err != nil {
		return nil, err
	}
	return NewBlockMode(blk, iv, unix.ALG_OP_DECRYPT)
}
