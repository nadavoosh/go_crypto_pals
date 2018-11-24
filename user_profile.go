package cryptopals

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

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
	return DumpCookie(map[string]string{"email": p.user, "uid": strconv.FormatInt(int64(p.uid), 10), "role": string(p.role)})
}

func sortStringMap(m map[string]string) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func DumpCookie(m map[string]string) string {
	return fmt.Sprintf("email=%s&uid=%s&role=%s", m["email"], m["uid"], m["role"])
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

func ProfileFor(email []byte) Profile {
	r := strings.NewReplacer("=", "", "&", "")
	return Profile{user: fmt.Sprintf(r.Replace(string(email))), uid: 10, role: User}
}

func EncryptedProfileFor(email []byte) (EncryptedText, error) {
	p := ProfileFor(email).Encode()
	return Encrypt(ECB, PlainText{plaintext: []byte(p), key: FixedKey})
}

func getBytesOfLen(l int) []byte {
	return bytes.Repeat(ByteA, l)
}

func BuildAdminProfile(email string) (EncryptedText, error) {
	// produce email=XXXXXXX block and
	// produce XXXXXXX&uid=10&role= block
	t, err := EncryptedProfileFor(getBytesOfLen(2*aes.BlockSize - len("email=&uid=10&role=")))
	if err != nil {
		return EncryptedText{}, err
	}
	emailUIDBlock := t.ciphertext[0 : 2*aes.BlockSize]
	// produce adminPPPPPP block
	a := PKCSPadding([]byte("admin"), aes.BlockSize)
	emailStub := append(getBytesOfLen(aes.BlockSize-len("email=")), a...)
	t, err = EncryptedProfileFor(emailStub)
	if err != nil {
		return EncryptedText{}, err
	}
	adminBlock := t.ciphertext[aes.BlockSize : 2*aes.BlockSize]
	return EncryptedText{ciphertext: append(emailUIDBlock, adminBlock...), key: FixedKey, padding: PKCS}, err
}
