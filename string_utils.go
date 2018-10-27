package set1

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
)

// HexToBytes converts a hex string to bytes
func HexToBytes(s string) []byte {
	src := []byte(s)
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dst, src)
	if err != nil {
		log.Fatal(err)
	}
	return dst
}

// HexToBase64 converts a hex string to a base64 string
func HexToBase64(s string) string {
	return base64.StdEncoding.EncodeToString(HexToBytes(s))
}

// HexFixedXor takes two equal-length hex strings and produces their XOR combination.
func HexFixedXor(hexString1, hexString2 string) (string, error) {
	if len(hexString1) != len(hexString2) {
		return "", errors.New("FixedXor requires hex strings of equal length")
	}
	b, err := FixedXor(HexToBytes(hexString1), HexToBytes(hexString2))
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
