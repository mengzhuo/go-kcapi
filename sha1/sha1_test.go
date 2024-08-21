package sha1_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/mengzhuo/go-kcapi/sha1"
)

func TestSHashSHA1(t *testing.T) {
	buf := make([]byte, os.Getpagesize())
	rand.Read(buf)
	kh, err := sha1.New()
	if err != nil {
		t.Skip(err)
	}
	kh.Write(buf)
	kh.Write(buf) // double write for msg handle
	khr := kh.Sum(nil)

	cmd := exec.Command("sha1sum")
	cmd.Stdin = bytes.NewReader(bytes.Repeat(buf, 2))
	out, err := cmd.Output()
	f := string(bytes.Fields(out)[0])
	if f != fmt.Sprintf("%x", khr) {
		t.Errorf("%s != %x", f, khr)
	}
}

func TestSHashSHA1File(t *testing.T) {
	kh, err := sha1.New()
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

	out, err := exec.Command("sha1sum", tf.Name()).Output()
	if err != nil {
		t.Fatal(err)
	}

	field := string(bytes.Fields(out)[0])
	if field != fmt.Sprintf("%x", khr) {
		t.Errorf("%s != %x", field, khr)
	}
}

var bechSize = []int{8, 1024, 8192, 16384}
var buf = make([]byte, 16384)

func BenchmarkSHashSHA1(b *testing.B) {
	for _, bs := range bechSize {
		b.Run(fmt.Sprintf("%d", bs), func(b *testing.B) {
			sum := make([]byte, bs)
			bench, _ := sha1.New()
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
