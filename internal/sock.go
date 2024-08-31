package internal

import "golang.org/x/sys/unix"

func NewAlgSock(name string, algtype string, op func(fd int) error) (opfd uintptr, addr *unix.SockaddrALG, err error) {

	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return 0, nil, err
	}
	defer unix.Close(fd)

	addr = &unix.SockaddrALG{Type: algtype, Name: name}
	err = unix.Bind(fd, addr)
	if err != nil {
		return 0, nil, err
	}

	if op != nil {
		err = op(fd)
		if err != nil {
			return 0, nil, err
		}
	}

	bfd, _, eno := unix.Syscall(unix.SYS_ACCEPT, uintptr(fd), 0, 0)
	if eno != 0 {
		return 0, nil, unix.Errno(eno)
	}
	return bfd, addr, nil
}
