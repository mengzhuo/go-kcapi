package sha3_512_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/mengzhuo/go-kcapi/sha3_512"
)

func TestSHashSHA3_512(t *testing.T) {
	buf := make([]byte, os.Getpagesize())
	rand.Read(buf)
	kh, err := sha3_512.New()
	if err != nil {
		t.Skip(err)
	}
	kh.Write(buf)
	kh.Write(buf) // double write for msg handle
	khr := kh.Sum(nil)

	cmd := exec.Command("openssl", "dgst", "-sha3-512")
	cmd.Stdin = bytes.NewReader(bytes.Repeat(buf, 2))
	out, _ := cmd.Output()
	f := string(bytes.Fields(out)[1])
	if f != fmt.Sprintf("%x", khr) {
		t.Errorf("%s != %x", f, khr)
	}
}

func TestSHashSHA3_512File(t *testing.T) {
	kh, err := sha3_512.New()
	if err != nil {
		t.Skip(err)
	}

	tf, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())

	n, err := io.CopyN(tf, rand.Reader, 16<<20)
	if err != nil {
		t.Error(n, err)
	}

	tf.Sync()
	tf.Seek(0, io.SeekStart)

	io.Copy(kh, tf)
	khr := kh.Sum(nil)

	out, err := exec.Command("openssl", "dgst", "-sha3-512", tf.Name()).Output()
	if err != nil {
		t.Fatal(err)
	}

	field := string(bytes.Fields(out)[1])
	if field != fmt.Sprintf("%x", khr) {
		t.Errorf("%s != %x", field, khr)
	}
}

var bechSize = []int{8, 1024, 8192, 16384}
var buf = make([]byte, 16384)

func BenchmarkSHashSHA3_512(b *testing.B) {
	for _, bs := range bechSize {
		b.Run(fmt.Sprintf("%d", bs), func(b *testing.B) {
			sum := make([]byte, bs)
			bench, _ := sha3_512.New()
			b.ReportAllocs()
			b.ResetTimer()
			b.SetBytes(int64(bs))
			for i := 0; i < b.N; i++ {
				bench.Reset()
				bench.Write(buf[:bs])
				bench.Sum(sum[:0])
			}
		})
	}
}

var fileSize = []int{1 << 20, 4 << 20, 16 << 20, 64 << 20}

func BenchmarkSHashSHA3_512File(b *testing.B) {
	for _, bs := range fileSize {
		b.Run(fmt.Sprintf("%d", bs), func(b *testing.B) {
			tmp, err := os.CreateTemp("", "")
			if err != nil {
				b.Fatal(err)
			}
			defer os.Remove(tmp.Name())

			io.CopyN(tmp, rand.Reader, int64(bs))
			tmp.Sync()

			bench, err := sha3_512.New()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()

			b.SetBytes(int64(bs))
			for i := 0; i < b.N; i++ {
				bench.Reset()
				tmp.Seek(0, io.SeekStart)
				io.Copy(bench, tmp)
				bench.Sum(nil)
			}
		})
	}
}
