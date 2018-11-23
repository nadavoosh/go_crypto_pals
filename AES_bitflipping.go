package cryptopals

import (
	"bytes"
	"fmt"
	"strings"
)

func escape(input string) []byte {
	r := strings.NewReplacer("=", "\\=", ";", "\\;")
	return []byte(r.Replace(input))
}

func unescape(input string) string {
	r := strings.NewReplacer("\\=", "=", "\\;", ";")
	return r.Replace(input)
}

func EncryptUserData(input []byte) (EncryptedText, error) {
	prepend := []byte("comment1=cooking%20MCs;userdata=")
	after := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	plaintext := append(prepend, append(escape(string(input)), after...)...)
	return Encrypt(CBC, PlainText{
		plaintext: plaintext,
		key:       FixedKey,
	})
}

func splitString(s, sep string) []string {
	var sp []string
	var prev int
	for i := 0; i < len(s); i++ {
		isLast := i == len(s)-1
		isTerminal := string(s[i]) == sep || isLast
		isEscaped := i-1 > 0 && string(s[i-1]) == "\\" && !isLast
		if isTerminal && !isEscaped {
			var add int
			if isLast {
				add = 1
			}
			sp = append(sp, s[prev:i+add])
			prev = i + 1
		}
	}
	return sp
}

func parseString(s string) map[string]string {
	m := make(map[string]string)
	st := splitString(s, ";")
	// fmt.Printf("s is %s\n", s)
	for _, pair := range st {
		p := splitString(pair, "=")
		if len(p) > 1 {
			m[unescape(p[0])] = unescape(p[1])
		} else {
			fmt.Printf("No `=` found in %s\n", pair)
		}

	}
	return m
}

func DetectAdminString(e EncryptedText) (bool, error) {
	plain, err := Decrypt(CBC, e)
	if err != nil {
		return false, err
	}
	m := parseString(string(plain.plaintext))
	if _, ok := m["admin"]; ok {
		return true, nil
	}
	return false, nil
}

func FlipBitsToHide(block []byte) []byte {
	return FlexibleXor(block, AByteBlock())
}

func ModifyCiphertextForAdmin(e EncryptedText) (EncryptedText, error) {
	chunks := ChunkForAES(e.ciphertext)
	chunkToFlip := 2 // TODO: calculate this value, by figuring out the length of prepended bytes
	flippedCiphertext := FlipBitsToHide(chunks[chunkToFlip])
	chunks[chunkToFlip] = flippedCiphertext
	ret := e
	ret.ciphertext =bytes.Join(chunks, nil)
	return ret, nil
}
