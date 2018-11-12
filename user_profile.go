package cryptopals

import (
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
	var cookie []string
	// To store the keys in slice in sorted order
	for _, k := range sortStringMap(m) {
		cookie = append(cookie, fmt.Sprintf("%s=%s", k, m[k]))
	}
	return strings.Join(cookie, "&")
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
