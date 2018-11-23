package cryptopals

import (
	"crypto/aes"
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
	return Encrypt(CBC, PlainText{
		plaintext: append(prepend, append(escape(string(input)), after...)...),
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
	for _, pair := range st {
		p := splitString(pair, "=")
		m[unescape(p[0])] = unescape(p[1])
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

func BitflipForAdmin(original []byte, e EncryptedText) (EncryptedText, error) {
	// _, _, err := GetPaddingLength(EncryptUserData, aes.BlockSize)
	if err != nil {
		return EncryptedText{}, err
	}
	return EncryptedText{
		ciphertext: e.ciphertext,
		iv:         e.iv,
		key:        e.key,
	}, nil
}
