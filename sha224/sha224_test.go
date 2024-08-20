package sha224_test

import (
	"fmt"
	"testing"

	"github.com/mengzhuo/go-kcapi/sha224"
)

var SHash = map[string]string{

	`foo, bar are temporary values in computer programing`:`61358f3d4f62bc822faadde78756237ac199990faaf1bd335b22ee49`,

	`quick fox jump over the lazy dog`:`533550497d7fa7b6f9405f5b53b29ed84bac54a70c4101d6257de3f1`,

}

func TestSHashSHA224(t *testing.T) {
	for k, v := range SHash {
		kh, err := sha224.New()
		if err != nil {
			t.Skip(err)
		}
		kh.Write([]byte(k))
		khr := kh.Sum(nil)
		khhex := fmt.Sprintf("%x", khr)
		if v != khhex {
			t.Errorf("sha224(%s) = %x, expect %x", k, khr, v)
		}
	}
}

var bechSize = []int{8, 1024, 8192, 16384}
var buf = make([]byte, 16384)

func BenchmarkSHashSHA224(b *testing.B) {
	for _, bs := range bechSize {
		b.Run(fmt.Sprintf("%d", bs), func(b *testing.B) {
			sum := make([]byte, bs)
			bench, _ := sha224.New()
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
