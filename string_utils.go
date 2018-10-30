package set1

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
)

type HexEncoded struct {
	hexString string
}

func (h HexEncoded) getBytes() []byte {
	src := []byte(h.hexString)
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dst, src)
	if err != nil {
		log.Fatal(err)
	}
	return dst
}

// HexToBase64 converts a hex string to a base64 string
func HexToBase64(h HexEncoded) string {
	return base64.StdEncoding.EncodeToString(h.getBytes())
}

// HexFixedXor takes two equal-length hex strings and produces their XOR combination.
func HexFixedXor(hexString1, hexString2 HexEncoded) (string, error) {
	if len(hexString1.hexString) != len(hexString2.hexString) {
		return "", errors.New("FixedXor requires hex strings of equal length")
	}
	b, err := FixedXor(hexString1.getBytes(), hexString2.getBytes())
	return fmt.Sprintf("%x", b), err
}

// FixedXor takes two equal-length byte arrays strings and produces their XOR combination.
func FixedXor(b1, b2 []byte) ([]byte, error) {
	if err := AssertEqualLen(b1, b2); err != nil {
		return nil, err
	}
	b := make([]byte, len(b1))
	for i := range b {
		b[i] = b1[i] ^ b2[i]
	}
	return b, nil
}

// AssertEqualLen returns an error if two byte slices are of different length
func AssertEqualLen(b1, b2 []byte) error {
	if len(b1) != len(b2) {
		return errors.New("fixedXorBytes requires byte slices of equal length")
	}
	return nil
}
