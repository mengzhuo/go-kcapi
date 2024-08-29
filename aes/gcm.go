package aes

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/mengzhuo/go-kcapi/aead"
	"github.com/mengzhuo/go-kcapi/internal"
	"golang.org/x/sys/unix"
)

const (
	gcmStandardNonceSize = 12
	gcmMinimumTagSize    = 12
	gcmTagSize           = 16
	gcmBlockSize         = 16
)

type GCM struct {
	h aead.Handle
}

func (g *GCM) NonceSize() int {
	return g.h.NonceSize
}

func (g *GCM) Overhead() int {
	return g.h.TagSize
}

func newGCM(key []byte, nonceSize int, tagSize int) (*GCM, error) {
	if tagSize < gcmMinimumTagSize || tagSize > gcmBlockSize {
		return nil, errors.New("gcm(aes): incorrect tag size given to GCM")
	}

	if nonceSize <= 0 {
		return nil, errors.New("gcm(aes): the nonce size can't have zero length")
	}

	h, err := aead.NewHandle("gcm(aes)", key, nonceSize, tagSize, gcmBlockSize)
	if err != nil {
		return nil, err
	}
	return &GCM{h: *h}, nil
}

func NewGCM(key []byte) (*GCM, error) {
	return newGCM(key, gcmStandardNonceSize, gcmTagSize)
}

func NewGCMWithNonceSize(key []byte, size int) (*GCM, error) {
	return newGCM(key, size, gcmTagSize)
}

func NewGCMWithTagSize(key []byte, size int) (*GCM, error) {
	return newGCM(key, gcmStandardNonceSize, size)
}

func (g *GCM) Seal(dst, nonce, plaintext, ad []byte) (r []byte) {

	if len(nonce) != g.h.NonceSize {
		panic("nonce size not matched")
	}

	oob := bytes.NewBuffer(internal.CipherOperation(unix.ALG_OP_ENCRYPT))
	oob.Write(internal.CipherIV(nonce))
	oob.Write(internal.CipherAEADAssocLen(len(ad)))

	pbuf := bytes.NewBuffer(ad)
	pbuf.Write(plaintext)
	err := unix.Sendmsg(int(g.h.Opfd),
		pbuf.Bytes(),
		oob.Bytes(), g.h.Addr, 0)

	if err != nil {
		panic(g.h.Name + " sendmsg error: " + err.Error())
	}

	rs := len(ad) + g.h.TagSize + len(plaintext)

	if len(dst) >= rs {
		r = dst[:rs]
	} else {
		r = make([]byte, rs)
	}

	_, err = unix.Read(int(g.h.Opfd), r)
	if err != nil {
		panic(g.h.Name + " read error: " + err.Error())
	}
	r = r[len(ad):]
	return
}

func (g *GCM) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {

	if len(nonce) != g.h.NonceSize {
		return nil, fmt.Errorf("%s: nonce size not matched", g.h.Name)
	}

	oob := bytes.NewBuffer(internal.CipherOperation(unix.ALG_OP_DECRYPT))
	oob.Write(internal.CipherIV(nonce))
	oob.Write(internal.CipherAEADAssocLen(len(ad)))

	pbuf := bytes.NewBuffer(ad)
	pbuf.Write(ciphertext)

	err := unix.Sendmsg(int(g.h.Opfd),
		pbuf.Bytes(),
		oob.Bytes(), g.h.Addr, 0)

	if err != nil {
		return nil, errors.Join(fmt.Errorf("%s: open sendmsg error", g.h.Name), err)
	}

	rs := len(ad) + len(ciphertext) - g.h.TagSize

	var r []byte
	if len(dst) >= rs {
		r = dst[:rs]
	} else {
		r = make([]byte, rs)
	}

	_, err = unix.Read(int(g.h.Opfd), r)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%s: open read error", g.h.Name), err)
	}
	return r[len(ad):], nil
}
