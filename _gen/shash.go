// go:build ignore
package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

type shash struct {
	Name        string
	Description string
	BlockSize   int
	DigestSize  int
	TestCases   map[string]string
}

var testcases = []string{
	"quick fox jump over the lazy dog",
	"foo, bar",
}

var shashTab = []shash{
	{"md5", "MD5 hash algorithm", 64, 16, nil},
	{"sha1", "SHA-1 hash algorithm", 64, 20, nil},
	{"sha224", "SHA-2 224 hash algorithm", 64, 28, nil},
	{"sha256", "SHA-2 256 hash algorithm", 64, 32, nil},
	{"sha384", "SHA-2 384 hash algorithm", 128, 48, nil},
	{"sha512", "SHA-2 512 hash algorithm", 128, 64, nil},
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

func runHash(hcmd string, v string) string {
	var cmd string
	var args []string
	var fields = 0
	switch hcmd {
	case "sha3-256", "sha3-384", "sha3-512":
		cmd = "openssl"
		args = append(args, "dgst", "-"+hcmd)
		fields = 1
	default:
		cmd = hcmd + "sum"
	}
	c := exec.Command(cmd, args...)
	c.Stdin = strings.NewReader(v)
	o, err := c.Output()
	if err != nil {
		panic(err)
	}
	return string(bytes.Fields(o)[fields])
}

func main() {
	flag.Parse()
	tmpl := template.Must(template.ParseGlob(*ftmpl))
	testTmpl := template.Must(template.New("shash_test.tmpl").
		Funcs(template.FuncMap{"title": strings.ToTitle}).ParseFiles(*testTmpl))

	for _, h := range shashTab {
		for _, v := range testcases {
			if h.TestCases == nil {
				h.TestCases = make(map[string]string)
			}
			h.TestCases[v] = runHash(h.Name, v)
			log.Printf("%s(%s) = %q", h.Name, v, h.TestCases[v])
		}

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
