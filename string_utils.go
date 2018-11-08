package cryptopals

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
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

func Min(x, y int) int {
	if x > y {
		return y
	}
	return x
}

func Max(x, y int) int {
	if x > y {
		return x
	}
	return y
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

func PKCSPadString(s string, blocksize int) string {
	return string(PKCSPadding([]byte(s), blocksize))
}

func PKCSPadding(b []byte, blocksize int) []byte {
	add := blocksize - (len(b) % blocksize)
	return append(b, FillByteSlice(add, byte(add))...)
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

type ProfileRole string

const (
	User  ProfileRole = "user"
	Admin ProfileRole = "admin"
)

type Profile struct {
	user string
	uid  int
	role ProfileRole
}

func (p Profile) Encode() string {
	return fmt.Sprintf("email=%s&uid=%d&role=%s", p.user, p.uid, p.role)
}

func ParseCookie(s string) map[string]string {
	m := make(map[string]string)
	st := strings.Split(s, "&")
	for _, pair := range st {
		p := strings.Split(pair, "=")
		m[p[0]] = p[1]
	}
	return m
}

func ProfileFor(email string) Profile {
	r := strings.NewReplacer("=", "", "&", "")
	email = fmt.Sprintf(r.Replace(email))
	return Profile{user: email, uid: 10, role: User}
}
