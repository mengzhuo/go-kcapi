# Go KCAPI

Pure Go binding for Linux Kernel Crypto API
Use KCAPI like stdandary Go crypto/* do.

### Usage

```go
import "github.com/mengzhuo/go-kcapi/sha1"

func main() {
    h, _ := sha1.New()
    h.Write("Hello World")
    r := h.Sum(nil)
    fmt.Println("%x", r)
}

```

### Roadmap

* [x] shash
* [ ] rng
* [ ] cipher
* [ ] skcipher
* [ ] akcipher
* [ ] kpp
* [ ] scomp
* [ ] compression


### Author
[Meng Zhuo](https://github.com/mengzhuo)
