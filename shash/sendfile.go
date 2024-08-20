package shash

import (
	"errors"
	"fmt"
	"io"
	"syscall"
)

func (h *Hash) ReadFrom(r io.Reader) (int64, error) {
	n, err, handled := sendfile(h, r)
	if handled {
		return int64(n), err
	}
	return 0, errors.Join(err, fmt.Errorf("syscall failed"))
}

type hasFD interface {
	Fd() uintptr
}

// ref: go/src/net/splice_linux.go
func sendfile(h *Hash, r io.Reader) (written int, err error, handled bool) {
	var remain int64 = 1<<63 - 1 // by default, copy until EOF
	lr, ok := r.(*io.LimitedReader)
	if ok {
		remain, r = lr.N, lr.R
		if remain <= 0 {
			return 0, nil, true
		}
	}

	has, ok := r.(hasFD)
	if !ok {
		return 0, nil, false
	}
	rfd := has.Fd()
	written, err = syscall.Sendfile(h.hashfd, int(rfd), nil, int(remain))
	if err != nil {
		return 0, err, false
	}
	if lr != nil {
		lr.N -= int64(written)
	}
	return written, err, true
}
