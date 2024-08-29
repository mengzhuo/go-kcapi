// Copyright 2024 Meng Zhuo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package aes implement cipher AES related cryptograph suite like GCM/CBC
package aes

import (
	"github.com/mengzhuo/go-kcapi/skcipher"
)

const cbc = "cbc(aes)"

func NewCBCEncrypter(key []byte, iv []byte) (*skcipher.BlockMode, error) {
	err := checkKeySize(key)
	if err != nil {
		return nil, err
	}
	return skcipher.NewCBCEncrypter(cbc, key, iv, BlockSize)
}

func NewCBCDecrypter(key []byte, iv []byte) (*skcipher.BlockMode, error) {
	err := checkKeySize(key)
	if err != nil {
		return nil, err
	}
	return skcipher.NewCBCDecrypter(cbc, key, iv, BlockSize)
}
