package cryptopals

import (
	"fmt"
)

type Padding int

const (
	None Padding = 0
	PKCS Padding = 1
)

func RemovePKCSPadding(b []byte) []byte {
	if b == nil {
		fmt.Println("nil slice passed to RemovePKCSPadding")
	}
	paddingCount := int(b[len(b)-1])
	return b[:len(b)-paddingCount]
}

func PKCSPadString(s string, blocksize int) string {
	return string(PKCSPadding([]byte(s), blocksize))
}

func PKCSPadding(b []byte, blocksize int) []byte {
	add := blocksize - (len(b) % blocksize)
	return append(b, FillByteSlice(add, byte(add))...)
}

func ValidatePKCS(b []byte) bool {
	if b == nil {
		fmt.Println("nil slice passed to ValidatePKCS")
		return false
	}
	claimedPaddingCount := int(b[len(b)-1])
	for j := len(b) - claimedPaddingCount; j < len(b)-1; j++ {
		if int(b[j]) != claimedPaddingCount {
			return false
		}
	}
	return true
}