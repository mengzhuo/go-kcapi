package aes

import "strconv"

const (
	BlockSize = 16
)

type KeySizeError int

func checkKeySize(key []byte) error {
	switch l := len(key); l {
	case 16, 24, 32:
		return nil
	default:
		return KeySizeError(l)
	}
}

func (k KeySizeError) Error() string {
	return "kcapi/aes: invalid key size " + strconv.Itoa(int(k))
}
