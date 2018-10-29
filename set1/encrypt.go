package set1

import (
	"bytes"
	"fmt"
	"log"
)

// RepeatingKeyXor sequentially applies each byte of the key to the plaintext and returns the result hex encoded
func RepeatingKeyXor(plain string, key string) (string, error) {
	return RepeatingKeyXorBytes([]byte(plain), []byte(key))
}

func RepeatingKeyXorBytes(p, key []byte) (string, error) {
	b, err := FixedXor(p, repeatBytesToLegnth(key, len(p)))
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
