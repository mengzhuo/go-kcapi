// go:build ignore
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
}

type shash struct {
	Name        string
	Description string
	BlockSize   int
	DigestSize  int
	System      System
}

var shashTab = []shash{
	{"md5", "MD5 hash algorithm", 64, 16, System{"md5sum", 0}},
	{"sha1", "SHA-1 hash algorithm", 64, 20, System{"sha1sum", 0}},
	{"sha224", "SHA-2 224 hash algorithm", 64, 28, System{"sha224sum", 0}},
	{"sha256", "SHA-2 256 hash algorithm", 64, 32, System{"sha256sum", 0}},
	{"sha384", "SHA-2 384 hash algorithm", 128, 48, System{"sha384sum", 0}},
	{"sha512", "SHA-2 512 hash algorithm", 128, 64, System{"sha512sum", 0}},
	//{"sha3-256", "SHA-3 256 bits hash algorithm", 136, 32, nil},
	//{"sha3-384", "SHA-3 384 bits hash algorithm", 104, 48, nil},
	//{"sha3-512", "SHA-3 512 bits hash algorithm", 72, 64, nil},
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

		dir := filepath.Join(*outdir, h.Name)
		os.MkdirAll(dir, 0755)
		f, err := os.Create(filepath.Join(dir, h.Name+".go"))
		if err != nil {
			log.Fatal(err)
		}
		err = tmpl.Execute(f, h)
		if err != nil {
			log.Fatal(err)
		}
		f.Close()

		f, err = os.Create(filepath.Join(dir, h.Name+"_test.go"))
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
