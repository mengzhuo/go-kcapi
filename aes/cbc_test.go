package aes_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	kaes "github.com/mengzhuo/go-kcapi/aes"
)

const c = "abcdefghijklmnop"

func TestCBCEncrypt(t *testing.T) {
	enc, err := kaes.NewCBCEncrypter(bytes.Repeat([]byte(c), 2), []byte(c))
	if err != nil {
		t.Fatal(err)
	}
	p := bytes.Repeat([]byte(c), 256)
	enc.CryptBlocks(p[:2048], p[:2048])
	enc.CryptBlocks(p[2048:], p[2048:])

	// Std
	block, err := aes.NewCipher(bytes.Repeat([]byte(c), 2))
	if err != nil {
		t.Fatal(err)
	}
	sp := bytes.Repeat([]byte(c), 256)
	se := cipher.NewCBCEncrypter(block, []byte(c))
	if err != nil {
		t.Fatal(err)
	}
	se.CryptBlocks(sp, sp)
	if !bytes.Equal(sp, p) {
		t.Errorf("expecting=%x got=%x", sp[:10], p[:10])
	}
}

func BenchmarkCBCEncrypto(b *testing.B) {
	enc, err := kaes.NewCBCEncrypter([]byte(c), []byte(c))
	if err != nil {
		b.Fatal(err)
	}
	p := make([]byte, 4096)
	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(4096)
	for i := 0; i < b.N; i++ {
		enc.CryptBlocks(p, p)
	}
}

func BenchmarkCBCStdEncrypto(b *testing.B) {
	block, err := aes.NewCipher([]byte(c))
	if err != nil {
		b.Fatal(err)
	}
	sp := make([]byte, 4096)
	se := cipher.NewCBCEncrypter(block, []byte(c))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(4096)
	for i := 0; i < b.N; i++ {
		se.CryptBlocks(sp, sp)
	}
}
