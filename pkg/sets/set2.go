package sets

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/nadavoosh/go_crypto_pals/pkg/padding"
	"github.com/nadavoosh/go_crypto_pals/pkg/pals"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

func appendAndEncrypt(a []byte) pals.EncryptionFn {
	return func(plain []byte) (pals.Ciphertext, error) {
		d := pals.NewAESECB(pals.Plaintext(append(plain, a...)))
		return d.Encrypt(utils.FixedKey)
	}
}

func prependAndAppendAndEncrypt(a []byte) pals.EncryptionFn {
	return func(plain []byte) (pals.Ciphertext, error) {
		d := pals.NewAESECB(pals.Plaintext(append(append(utils.FixedBytes, plain...), a...)))
		return d.Encrypt(utils.FixedKey)
	}
}

var YELLOWSUBMARINE = "YELLOW SUBMARINE"

type profileRole string

const (
	user  profileRole = "user"
	admin profileRole = "admin"
)

type profile struct {
	user string
	uid  int
	role profileRole
}

func (p profile) encode() string {
	return dumpCookie(map[string]string{"email": p.user, "uid": strconv.FormatInt(int64(p.uid), 10), "role": string(p.role)})
}

func sortStringMap(m map[string]string) []string {
	var Keys []string
	for k := range m {
		Keys = append(Keys, k)
	}
	sort.Strings(Keys)
	return Keys
}

func dumpCookie(m map[string]string) string {
	return fmt.Sprintf("email=%s&uid=%s&role=%s", m["email"], m["uid"], m["role"])
}

func parseCookie(s string) map[string]string {
	m := make(map[string]string)
	st := strings.Split(s, "&")
	for _, pair := range st {
		p := strings.Split(pair, "=")
		m[p[0]] = p[1]
	}
	return m
}

func profileFor(email []byte) profile {
	r := strings.NewReplacer("=", "", "&", "")
	return profile{user: fmt.Sprintf(r.Replace(string(email))), uid: 10, role: user}
}

func encryptedProfileFor(email []byte) (pals.Ciphertext, error) {
	p := profileFor(email).encode()
	return pals.NewAESECB(pals.Plaintext(p)).Encrypt(utils.FixedKey)
}

func getBytesOfLen(l int) []byte {
	return bytes.Repeat(utils.ByteA, l)
}

func buildAdminProfile(email string) (pals.Ciphertext, error) {
	// produce email=XXXXXXX block and
	// produce XXXXXXX&uid=10&role= block
	t, err := encryptedProfileFor(getBytesOfLen(2*aes.BlockSize - len("email=&uid=10&role=")))
	if err != nil {
		return nil, err
	}
	emailUIDBlock := t[0 : 2*aes.BlockSize]
	// produce adminPPPPPP block
	a := padding.PKCSPadding([]byte("admin"), aes.BlockSize)
	emailStub := append(getBytesOfLen(aes.BlockSize-len("email=")), a...)
	t, err = encryptedProfileFor(emailStub)
	if err != nil {
		return nil, err
	}
	adminBlock := t[aes.BlockSize : 2*aes.BlockSize]
	return pals.Ciphertext(append(emailUIDBlock, adminBlock...)), err
}

func getUserData(input []byte) []byte {
	prepend := []byte("comment1=cooking%20MCs;userdata=")
	after := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	return append(prepend, append([]byte(utils.Escape(string(input))), after...)...)
}

func encryptUserDataCBC(input []byte) (pals.Ciphertext, pals.IV, error) {
	p := getUserData(input)
	d := pals.AES_CBC{Plaintext: p}
	c, err := d.Encrypt(utils.FixedKey)
	return c, d.IV, err
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
		if len(p) > 1 {
			m[utils.Unescape(p[0])] = utils.Unescape(p[1])
		} else if len(p) == 1 {
			m[utils.Unescape(p[0])] = ""
		} else {
			fmt.Printf("No `=` found in %s\n", pair)
		}
	}
	return m
}

func detectAdminStringCBC(e pals.Ciphertext, iv pals.IV) (bool, error) {
	a := pals.AES_CBC{Ciphertext: e, IV: iv}
	plain, err := a.Decrypt(utils.FixedKey)
	if err != nil {
		return false, err
	}
	return detectAdminString(plain), nil
}

func detectAdminString(p []byte) bool {
	m := parseString(string(p))
	if _, ok := m["admin"]; ok {
		return true
	}
	return false
}

func flipBitsToHide(block []byte) []byte {
	return utils.FlexibleXor(block, pals.AByteBlock())
}

func modifyCiphertextForAdmin(Ciphertext []byte) ([]byte, error) {
	chunks := pals.ChunkForAES(Ciphertext)
	chunkToFlip := 2 // TODO: calculate this value, by figuring out the length of prepended bytes
	flippedCiphertext := flipBitsToHide(chunks[chunkToFlip])
	chunks[chunkToFlip] = flippedCiphertext
	return bytes.Join(chunks, nil), nil
}
