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
	kp := make([]byte, 32)
	krp := make([]byte, 32)
	copy(kp[:], c)
	copy(kp[16:], c)
	enc.CryptBlocks(krp, kp[:16])
	enc.CryptBlocks(krp[16:], kp[16:])

	// Std
	block, err := aes.NewCipher(bytes.Repeat([]byte(c), 2))
	if err != nil {
		t.Fatal(err)
	}
	sp := make([]byte, 32)
	copy(sp[:], c)
	copy(sp[16:], c)
	se := cipher.NewCBCEncrypter(block, []byte(c))
	if err != nil {
		t.Fatal(err)
	}
	se.CryptBlocks(sp[:16], sp[:16])
	se.CryptBlocks(sp[16:], sp[16:])
	if !bytes.Equal(sp, krp) {
		t.Errorf("expecting=%x got=%x", sp, krp)
	}
}

func BenchmarkCBCEncrypto(b *testing.B) {
	enc, err := kaes.NewCBCEncrypter([]byte(c), []byte(c))
	if err != nil {
		b.Fatal(err)
	}
	p := make([]byte, 16)
	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(16)
	for i := 0; i < b.N; i++ {
		enc.CryptBlocks(p, p)
	}
}

func BenchmarkCBCStdEncrypto(b *testing.B) {
	block, err := aes.NewCipher([]byte(c))
	if err != nil {
		b.Fatal(err)
	}
	sp := make([]byte, 16)
	se := cipher.NewCBCEncrypter(block, []byte(c))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(16)
	for i := 0; i < b.N; i++ {
		se.CryptBlocks(sp, sp)
	}
}
