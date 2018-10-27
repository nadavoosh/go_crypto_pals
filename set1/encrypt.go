package set1

import (
	"bytes"
	"fmt"
	"log"
)

// EncryptRepeatingKeyXor sequentially applies each byte of the key to the plaintext and returns the result hex encoded
func EncryptRepeatingKeyXor(plain string, key string) (string, error) {
	p := []byte(plain)
	b, err := FixedXor(p, repeatBytesToLegnth([]byte(key), len(p)))
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func repeatBytesToLegnth(b []byte, l int) []byte {
	res := [][]byte{bytes.Repeat(b, l/len(b)), b[:l%len(b)]}
	return bytes.Join(res, nil)
}
