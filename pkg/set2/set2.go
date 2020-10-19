package set2

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
	return func(plain []byte) (pals.Encrypted, error) {
		d := pals.NewAESECB(pals.Plain{Plaintext: append(plain, a...)})
		return d.Encrypt(utils.FixedKey)
	}
}

func prependAndAppendAndEncrypt(a []byte) pals.EncryptionFn {
	return func(plain []byte) (pals.Encrypted, error) {
		d := pals.NewAESECB(pals.Plain{Plaintext: append(append(utils.FixedBytes, plain...), a...)})
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

func encryptedProfileFor(email []byte) (pals.Encrypted, error) {
	p := profileFor(email).encode()
	return pals.NewAESECB(pals.Plain{Plaintext: []byte(p)}).Encrypt(utils.FixedKey)
}

func getBytesOfLen(l int) []byte {
	return bytes.Repeat(utils.ByteA, l)
}

func buildAdminProfile(email string) (pals.Encrypted, error) {
	// produce email=XXXXXXX block and
	// produce XXXXXXX&uid=10&role= block
	t, err := encryptedProfileFor(getBytesOfLen(2*aes.BlockSize - len("email=&uid=10&role=")))
	if err != nil {
		return pals.Encrypted{}, err
	}
	emailUIDBlock := t.Ciphertext[0 : 2*aes.BlockSize]
	// produce adminPPPPPP block
	a := padding.PKCSPadding([]byte("admin"), aes.BlockSize)
	emailStub := append(getBytesOfLen(aes.BlockSize-len("email=")), a...)
	t, err = encryptedProfileFor(emailStub)
	if err != nil {
		return pals.Encrypted{}, err
	}
	adminBlock := t.Ciphertext[aes.BlockSize : 2*aes.BlockSize]
	return pals.Encrypted{Ciphertext: append(emailUIDBlock, adminBlock...), Padding: padding.PKCS}, err
}
