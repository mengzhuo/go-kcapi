package procfs

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
)

const procPath = "/proc/crypto"

var (
	once       sync.Once
	cryptoList []Crypto
)

type Crypto struct {
	Name        string  `json:"name,omitempty"`
	AlignMask   *uint64 `json:"align_mask,omitempty"`
	Async       bool    `json:"async,omitempty"`
	BlockSize   *uint64 `json:"block_size,omitempty"`
	ChunkSize   *uint64 `json:"chunk_size,omitempty"`
	DigestSize  *uint64 `json:"digest_size,omitempty"`
	Driver      string  `json:"driver,omitempty"`
	GenIV       string  `json:"gen_iv,omitempty"`
	Internal    string  `json:"internal,omitempty"`
	IVSize      *uint64 `json:"iv_size,omitempty"`
	MaxAuthSize *uint64 `json:"max_auth_size,omitempty"`
	MaxKeySize  *uint64 `json:"max_key_size,omitempty"`
	MinKeySize  *uint64 `json:"min_key_size,omitempty"`
	Module      string  `json:"module,omitempty"`
	Priority    *int64  `json:"priority,omitempty"`
	RefCnt      *int64  `json:"ref_cnt,omitempty"`
	SeedSize    *uint64 `json:"seed_size,omitempty"`
	Type        string  `json:"type,omitempty"`
	WalkSize    *uint64 `json:"walk_size,omitempty"`
}

func Default() []Crypto {
	once.Do(func() {
		var err error
		cryptoList, err = Parse("")
		if err != nil {
			panic(err)
		}
	})
	return cryptoList
}

func Parse(p string) ([]Crypto, error) {
	if p == "" {
		p = procPath
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseProcFS(f)
}

func puint64(s string) (*uint64, error) {
	v, err := strconv.ParseUint(s, 0, 64)
	return &v, err
}

func pint64(s string) (*int64, error) {
	v, err := strconv.ParseInt(s, 0, 64)
	return &v, err
}

func parseProcFS(f *os.File) (l []Crypto, err error) {
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		if strings.TrimSpace(scan.Text()) == "" {
			continue
		}

		k, v, found := strings.Cut(scan.Text(), ":")
		if !found {
			continue
		}

		var t *Crypto
		if len(l) > 0 {
			t = &l[len(l)-1]
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "name":
			l = append(l, Crypto{Name: v})
		case "async":
			t.Async = v == "yes"
		case "blocksize":
			t.BlockSize, err = puint64(v)
		case "chunksize":
			t.ChunkSize, err = puint64(v)
		case "digestsize":
			t.DigestSize, err = puint64(v)
		case "geniv":
			t.GenIV = v
		case "internal":
			t.Internal = v
		case "ivsize":
			t.IVSize, err = puint64(v)
		case "maxauthsize":
			t.MaxAuthSize, err = puint64(v)
		case "max keysize":
			t.MaxKeySize, err = puint64(v)
		case "mix keysize":
			t.MinKeySize, err = puint64(v)
		case "module":
			t.Module = v
		case "priority":
			t.Priority, err = pint64(v)
		case "refcnt":
			t.RefCnt, err = pint64(v)
		case "seedsize":
			t.SeedSize, err = puint64(v)
		case "type":
			t.Type = v
		case "walksize":
			t.WalkSize, err = puint64(v)
		}

		if err != nil {
			return
		}
	}
	return
}
