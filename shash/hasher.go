// Copyright 2024 Meng Zhuo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package shash internal use for shash
package shash

import (
	"os"

	"github.com/mengzhuo/go-kcapi/internal"
	"golang.org/x/sys/unix"
)

type Hash struct {
	f      *os.File
	addr   *unix.SockaddrALG
	hashfd int
	name   string
	size   int
	bs     int
}

func (h *Hash) Sum(p []byte) []byte {
	if len(p) != 0 {
		h.Write(p)
	}
	h.f.Sync()
	r := make([]byte, h.size)
	h.f.Read(r)
	return r
}

func (h *Hash) Reset() {
	h.f.Write(nil)
}

func (h *Hash) Close() error {
	return h.f.Close()
}

func (h *Hash) Write(p []byte) (n int, err error) {
	err = unix.Sendto(h.hashfd, p, unix.MSG_MORE, h.addr)
	n = len(p)
	return
}

func (h *Hash) Size() int {
	return h.size
}

func (h *Hash) BlockSize() int {
	return h.bs
}

func NewHash(name string, size int, bs int) (*Hash, error) {

	hashfd, addr, err := internal.NewAlgSock(name, "hash", nil)
	if err != nil {
		return nil, err
	}

	// handler for close
	f := os.NewFile(hashfd, name)
	h := &Hash{
		f:      f,
		hashfd: int(hashfd),
		name:   name,
		addr:   addr,
		size:   size,
		bs:     bs,
	}
	return h, err
}
