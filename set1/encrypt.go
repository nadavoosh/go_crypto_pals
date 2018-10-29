package set1

import (
	"bytes"
	"fmt"
	"log"
)

// RepeatingKeyXor sequentially applies each byte of the key to the plaintext and returns the result hex encoded
func RepeatingKeyXor(plain, key string) (string, error) {
	res, err := RepeatingKeyXorBytes([]byte(plain), []byte(key))
	return fmt.Sprintf("%x", res), err
}

func RepeatingKeyXorBytes(p, key []byte) ([]byte, error) {
	b, err := FixedXor(p, repeatBytesToLegnth(key, len(p)))
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return b, nil
}

func repeatBytesToLegnth(b []byte, l int) []byte {
	res := [][]byte{bytes.Repeat(b, l/len(b)), b[:l%len(b)]}
	return bytes.Join(res, nil)
}
