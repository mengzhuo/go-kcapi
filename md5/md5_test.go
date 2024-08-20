package md5_test

import (
	"fmt"
	"testing"

	"github.com/mengzhuo/go-kcapi/md5"
)

var SHash = map[string]string{

	`foo, bar are temporary values in computer programing`: `d552d0c7d14ddfc2f3c9c21b30b14dcd`,

	`quick fox jump over the lazy dog`: `e077923f17b3309ebe5c9a3ef802fe37`,
}

func TestSHashMD5(t *testing.T) {
	for k, v := range SHash {
		kh, err := md5.New()
		if err != nil {
			t.Skip(err)
		}
		kh.Write([]byte(k))
		khr := kh.Sum(nil)
		khhex := fmt.Sprintf("%x", khr)
		if v != khhex {
			t.Errorf("md5(%s) = %x, expect %x", k, khr, v)
		}
	}
}

var bechSize = []int{8, 1024, 8192, 16384}
var buf = make([]byte, 16384)

func BenchmarkSHashMD5(b *testing.B) {
	for _, bs := range bechSize {
		b.Run(fmt.Sprintf("%d", bs), func(b *testing.B) {
			sum := make([]byte, bs)
			bench, _ := md5.New()
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
