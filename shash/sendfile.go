package shash

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
)

func (h *Hash) ReadFrom(r io.Reader) (int64, error) {
	n, err, handled := sendfile(h, r)
	if handled {
		return int64(n), err
	}
	// can't handle with sendfile, fallback to read
	buf := make([]byte, os.Getpagesize())
	var werr, rerr error
	var rn int
	for werr == nil && rerr == nil {
		rn, rerr = r.Read(buf)
		_, werr = h.Write(buf[:rn])
		n += rn
	}
	// skip io.EOF as std do
	if rerr == io.EOF {
		return int64(n), nil
	}
	return 0, errors.Join(err, fmt.Errorf("syscall failed"))
}

type hasFD interface {
	Fd() uintptr
}

func sendfile(h *Hash, r io.Reader) (written int, err error, handled bool) {
	var remain int64 = 1<<63 - 1 // by default, copy until EOF
	lr, ok := r.(*io.LimitedReader)
	if ok {
		remain, r = lr.N, lr.R
		if remain <= 0 {
			return 0, nil, true
		}
	}
	var rfd uintptr
	switch v := r.(type) {
	case *net.TCPConn:
		rf, _ := v.File()
		rfd = rf.Fd()
	case *net.UnixConn:
		addr := v.LocalAddr()
		if addr.Network() == "unix" {
			rf, _ := v.File()
			rfd = rf.Fd()
		}
	case hasFD:
		rfd = v.Fd()
	default:
		return 0, nil, false
	}

	written, err = syscall.Sendfile(h.hashfd, int(rfd), nil, int(remain))
	if err != nil {
		return 0, err, false
	}
	if lr != nil {
		lr.N -= int64(written)
	}
	return written, err, true
}
