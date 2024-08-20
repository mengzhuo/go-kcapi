package sha256_test

import (
	"fmt"
	"testing"

	"github.com/mengzhuo/go-kcapi/sha256"
)

var SHash = map[string]string{

	`foo, bar are temporary values in computer programing`: `fb93a75584591b49ff7579dc5cab32c953148544f21761abbf53d87766aa5085`,

	`quick fox jump over the lazy dog`: `61b168729ac240e31be802f2506a7c37bc2dcfada6352e0ba625d2006cfe85c2`,
}

func TestSHashSHA256(t *testing.T) {
	for k, v := range SHash {
		kh, err := sha256.New()
		if err != nil {
			t.Skip(err)
		}
		kh.Write([]byte(k))
		khr := kh.Sum(nil)
		khhex := fmt.Sprintf("%x", khr)
		if v != khhex {
			t.Errorf("sha256(%s) = %x, expect %x", k, khr, v)
		}
	}
}

var bechSize = []int{8, 1024, 8192, 16384}
var buf = make([]byte, 16384)

func BenchmarkSHashSHA256(b *testing.B) {
	for _, bs := range bechSize {
		b.Run(fmt.Sprintf("%d", bs), func(b *testing.B) {
			sum := make([]byte, bs)
			bench, _ := sha256.New()
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
