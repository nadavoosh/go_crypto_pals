package set1

import (
	"bytes"
	"fmt"
	"log"
)

// RepeatingKeyXor sequentially applies each byte of the key to the plaintext and returns the result hex encoded
func RepeatingKeyXor(plain string, key string) (string, error) {
	p := []byte(plain)
	return RepeatingKeyXorBytes(p, key)
}

func RepeatingKeyXorBytes(p []byte, key string) (string, error) {
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
