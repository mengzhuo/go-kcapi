package sha1_test

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/mengzhuo/go-kcapi/sha1"
)

var SHash = map[string]string{

	`foo, bar`: `532599fa0da64fb9f088830f8626d71dc6c077f0`,

	`quick fox jump over the lazy dog`: `84c7b0c197329f42869e7bd7567e84448215fef7`,
}

func TestSHashSHA1(t *testing.T) {
	for k, v := range SHash {
		kh, err := sha1.New()
		if err != nil {
			t.Skip(err)
		}
		kh.Write([]byte(k))
		khr := kh.Sum(nil)
		khhex := fmt.Sprintf("%x", khr)
		if v != khhex {
			t.Errorf("sha1(%s) = %x, expect %x", k, khr, v)
		}
	}
}

func TestSHashSHA1File(t *testing.T) {
	kh, err := sha1.New()
	f, err := os.Open("sha1.go")
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(kh, f)
	if err != nil {
		t.Error(n, err)
	}
	t.Logf("%x", kh.Sum(nil))
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
