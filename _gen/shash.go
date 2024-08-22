//go:build ignore

package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

type System struct {
	Command string
	Field   int
	Args    []string
}

type shash struct {
	Name        string
	Package     string
	Description string
	BlockSize   int
	DigestSize  int
	System      System
}

var shashTab = []shash{
	{"md5", "md5", "MD5 hash algorithm", 64, 16, System{"md5sum", 0, nil}},
	{"sha1", "sha1", "SHA-1 hash algorithm", 64, 20, System{"sha1sum", 0, nil}},
	{"sha224", "sha224", "SHA-2 224 hash algorithm", 64, 28, System{"sha224sum", 0, nil}},
	{"sha256", "sha256", "SHA-2 256 hash algorithm", 64, 32, System{"sha256sum", 0, nil}},
	{"sha384", "sha384", "SHA-2 384 hash algorithm", 128, 48, System{"sha384sum", 0, nil}},
	{"sha512", "sha512", "SHA-2 512 hash algorithm", 128, 64, System{"sha512sum", 0, nil}},
	{"sha3-256", "sha3b256", "SHA-3 256 bits hash algorithm", 136, 32,
		System{"openssl", 1, []string{"dgst", "-sha3-256"}}},
	{"sha3-384", "sha3b384", "SHA-3 384 bits hash algorithm", 104, 48,
		System{"openssl", 1, []string{"dgst", "-sha3-384"}}},
	{"sha3-512", "sha3b512", "SHA-3 512 bits hash algorithm", 72, 64,
		System{"openssl", 1, []string{"dgst", "-sha3-512"}}},
	{"blake2b-512", "blake2b512", "Blake2b 512 bits hash algorithm", 128, 64,
		System{"b2sum", 0, nil}},
}

var (
	fabs, _ = filepath.Abs(".")
	ftmpl   = flag.String("ftmpl",
		filepath.Join(fabs, "_gen", "shash.tmpl"), "shash template path")
	testTmpl = flag.String("test",
		filepath.Join(fabs, "_gen", "shash_test.tmpl"), "shash test template path")

	outdir = flag.String("dir", fabs, "output directory")
)

func main() {
	flag.Parse()
	tmpl := template.Must(template.ParseGlob(*ftmpl))
	testTmpl := template.Must(template.New("shash_test.tmpl").
		Funcs(template.FuncMap{"title": strings.ToTitle}).ParseFiles(*testTmpl))

	for _, h := range shashTab {

		dir := filepath.Join(*outdir, h.Package)
		os.MkdirAll(dir, 0755)
		f, err := os.Create(filepath.Join(dir, h.Package+".go"))
		if err != nil {
			log.Fatal(err)
		}
		err = tmpl.Execute(f, h)
		if err != nil {
			log.Fatal(err)
		}
		f.Close()

		f, err = os.Create(filepath.Join(dir, h.Package+"_test.go"))
		if err != nil {
			log.Fatal(err)
		}
		err = testTmpl.Execute(f, h)
		if err != nil {
			log.Fatal(err)
		}
		f.Close()
	}
}
