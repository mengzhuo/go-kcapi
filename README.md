# Go KCAPI

Pure Go binding for Linux Kernel Crypto API

Use KCAPI like standary Go crypto/* do.

### Usage

```go
package main

import (
    "fmt"
    "github.com/mengzhuo/go-kcapi/sha1"
)

func main() {
    h, _ := sha1.New()
    h.Write([]byte("Hello World"))
    r := h.Sum(nil)
    fmt.Printf("%x", r) // 0a4d55a8d778e5022fab701977c5d840bbc486d0
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
