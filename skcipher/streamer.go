// Copyright 2024 Meng Zhuo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package skcipher internal use for kcapi
package skcipher

import (
	"os"

	"github.com/mengzhuo/go-kcapi/internal"
)

type Stream struct {
	Block *Block
	File  *os.File
	Op    int
}

func (s *Stream) Read(p []byte) (n int, err error) {
	return s.File.Read(p)
}

func (s *Stream) Write(p []byte) (n int, err error) {
	return s.File.Write(p)
}

func (s *Stream) XORKeyStream(dst, src []byte) {
	_, err := s.Write(src)
	if err != nil {
		panic(err)
	}
	_, err = s.Read(dst)
	if err != nil {
		panic(err)
	}
}

func NewStreamReader(name string, key, iv []byte, bs int, op int) (s *Stream, err error) {
	blk, err := NewBlock(name, key, bs)
	if err != nil {
		return
	}

	err = internal.SendMsg(blk.bfd,
		internal.CipherOperation(op),
		internal.CipherIV(iv))

	if err != nil {
		return
	}
	f := os.NewFile(blk.bfd, name)
	return &Stream{
		Block: blk,
		File:  f,
		Op:    op,
	}, err
}
