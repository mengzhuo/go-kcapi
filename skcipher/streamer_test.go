package skcipher_test

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"testing"

	"github.com/mengzhuo/go-kcapi/skcipher"
	"golang.org/x/sys/unix"
)

func TestCFB(t *testing.T) {

	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("some plaintext")

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// func NewStreamReader(name string, key, iv []byte, bs int, op int, rdr io.Reader)
	s, err := skcipher.NewStreamReader("ctr(aes)", key, iv, 16, unix.ALG_OP_ENCRYPT)
	if err != nil {
		t.Fatal(err)
	}

	s.Write(plaintext)

	_, err = s.Read(ciphertext[aes.BlockSize:])
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("%x", ciphertext[aes.BlockSize:])

	plaintext2 := make([]byte, len(plaintext))
	// func NewStreamReader(name string, key, iv []byte, bs int, op int, rdr io.Reader)
	ds, err := skcipher.NewStreamReader("ctr(aes)", key, iv, 16, unix.ALG_OP_DECRYPT)
	if err != nil {
		t.Fatal(err)
	}
	ds.Write(ciphertext[aes.BlockSize:])
	_, err = ds.Read(plaintext2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, plaintext2) {
		t.Errorf("%x != %x", plaintext, plaintext2)
	}
}
