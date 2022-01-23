package utils

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
)

type HexEncoded struct {
	HexString string
}

func (h HexEncoded) GetBytes() []byte {
	src := []byte(h.HexString)
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dst, src)
	if err != nil {
		log.Fatal(err)
	}
	return dst
}

// HexToBase64 converts a hex string to a base64 string
func HexToBase64(h HexEncoded) string {
	return base64.StdEncoding.EncodeToString(h.GetBytes())
}

// HexFixedXor takes two equal-length hex strings and produces their XOR combination.
func HexFixedXor(HexString1, HexString2 HexEncoded) (string, error) {
	b, err := FixedXor(HexString1.GetBytes(), HexString2.GetBytes())
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

func FlexibleXor(b1, b2 []byte) []byte {
	diff := len(b1) - len(b2)
	if diff > 0 {
		zeros := bytes.Repeat([]byte{0}, diff)
		x, _ := FixedXor(b1, append(b2, zeros...))
		return x
	}
	zeros := bytes.Repeat([]byte{0}, -diff)
	x, _ := FixedXor(append(b1, zeros...), b2)
	return x
}

// AssertEqualLen returns an error if two byte slices are of different length
func AssertEqualLen(b1, b2 []byte) error {
	if len(b1) != len(b2) {
		return fmt.Errorf("Requires byte slices of equal length, got %d and %d", len(b1), len(b2))
	}
	return nil
}

func ScanFile(filename string) ([]string, error) {
	var lines []string
	f, err := os.OpenFile(filename, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return lines, fmt.Errorf("open file error: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)

	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return lines, fmt.Errorf("scan file error: %v", err)
	}
	return lines, nil
}

func ReadBase64File(filename string) ([]byte, error) {
	lines, err := ScanFile(filename)
	if err != nil {
		return nil, err
	}
	decoded, err := ParseBase64(strings.Join(lines, ""))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func ParseBase64(l string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(l)
}

func FillByteSlice(l int, c byte) []byte {
	repeated := make([]byte, l)
	for i := 0; i < l; i++ {
		repeated[i] = c
	}
	return repeated
}

func SingleByteXor(h []byte, c byte) ([]byte, error) {
	repeated := FillByteSlice(len(h), c)
	return FixedXor(h, repeated)
}

func Escape(input string) string {
	r := strings.NewReplacer("=", "\\=", ";", "\\;")
	return r.Replace(input)
}

func Unescape(input string) string {
	r := strings.NewReplacer("\\=", "=", "\\;", ";")
	return r.Replace(input)
}

func IsAllAscii(input []byte) bool {
	for i := 0; i < len(input); i++ {
		if input[i] > 128 {
			return false
		}
	}
	return true
}
