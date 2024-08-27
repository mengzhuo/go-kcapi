package aes_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"testing"

	kaes "github.com/mengzhuo/go-kcapi/aes"
	"github.com/mengzhuo/go-kcapi/internal"
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

var benchSize = []int{1024, 4096, 8192, 8192 << 1, 16 * internal.PageSize}

func BenchmarkCBCEncrypto(b *testing.B) {
	enc, err := kaes.NewCBCEncrypter([]byte(c), []byte(c))
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range benchSize {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			p := make([]byte, size)
			b.ResetTimer()
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				enc.CryptBlocks(p, p)
			}
		})
	}
}

func BenchmarkCBCStdEncrypto(b *testing.B) {
	block, err := aes.NewCipher([]byte(c))
	if err != nil {
		b.Fatal(err)
	}
	se := cipher.NewCBCEncrypter(block, []byte(c))
	if err != nil {
		b.Fatal(err)
	}
	for _, size := range benchSize {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			sp := make([]byte, size)
			b.ResetTimer()
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				se.CryptBlocks(sp, sp)
			}
		})
	}
}
