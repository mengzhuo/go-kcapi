package sha384_test

import (
	"fmt"
	"testing"

	"github.com/mengzhuo/go-kcapi/sha384"
)

var SHash = map[string]string{

	`foo, bar`: `ec3eaab9ebf9564e663d5374eff570c9b7cff1bbd0a6144579d2ac317a1bdaa7398102b0fd12385ebcf5464fb531225d`,

	`quick fox jump over the lazy dog`: `38aff9da60fbfa4cf0cb28ef4d060fd26ae440c7d691726fab3dd81cf491ad601d7ac288cc74660f53f2011e81cceae1`,
}

func TestSHashSHA384(t *testing.T) {
	for k, v := range SHash {
		kh, err := sha384.New()
		if err != nil {
			t.Skip(err)
		}
		kh.Write([]byte(k))
		khr := kh.Sum(nil)
		khhex := fmt.Sprintf("%x", khr)
		if v != khhex {
			t.Errorf("sha384(%s) = %x, expect %x", k, khr, v)
		}
	}
}

var bechSize = []int{8, 1024, 8192, 16384}
var buf = make([]byte, 16384)

func BenchmarkSHashSHA384(b *testing.B) {
	for _, bs := range bechSize {
		b.Run(fmt.Sprintf("%d", bs), func(b *testing.B) {
			sum := make([]byte, bs)
			bench, _ := sha384.New()
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
