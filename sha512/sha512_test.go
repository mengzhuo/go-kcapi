package sha512_test

import (
	"fmt"
	"testing"

	"github.com/mengzhuo/go-kcapi/sha512"
)

var SHash = map[string]string{

	`foo, bar are temporary values in computer programing`:`d5cda4c763f9c77758015430bc8e3852da8cb2038d4b99efbd6a71fbaf4cef94ff0de22236cb824b7c6a154614babb1fdbca5685a4cc6ddd7711d2c8a0bc28d9`,

	`quick fox jump over the lazy dog`:`38453030abd6839ef5bf2294ef4ba2d3f72a845b866305409d97999f99fad3076ca2e69623b59328a850d574cd492f2bc5ca3476ba2262bfe5236a5370cdd522`,

}

func TestSHashSHA512(t *testing.T) {
	for k, v := range SHash {
		kh, err := sha512.New()
		if err != nil {
			t.Skip(err)
		}
		kh.Write([]byte(k))
		khr := kh.Sum(nil)
		khhex := fmt.Sprintf("%x", khr)
		if v != khhex {
			t.Errorf("sha512(%s) = %x, expect %x", k, khr, v)
		}
	}
}

var bechSize = []int{8, 1024, 8192, 16384}
var buf = make([]byte, 16384)

func BenchmarkSHashSHA512(b *testing.B) {
	for _, bs := range bechSize {
		b.Run(fmt.Sprintf("%d", bs), func(b *testing.B) {
			sum := make([]byte, bs)
			bench, _ := sha512.New()
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
