package cryptopals

import (
	"crypto/aes"
	"math/rand"
	"testing"
	"time"
)

func getEncryptionFunction(a []byte) func(plain []byte) (EncryptedText, error) {
	return func(plain []byte) (EncryptedText, error) {
		d := PlainText{plaintext: append(plain, a...), key: FixedKey}
		return EncryptECB(d)
	}
}

func getEncryptionFunctionHarder(a []byte) func(plain []byte) (EncryptedText, error) {
	return func(plain []byte) (EncryptedText, error) {
		d := PlainText{plaintext: append(append(FixedBytes, plain...), a...), key: FixedKey}
		return EncryptECB(d)
	}
}

var YELLOWSUBMARINE = "YELLOW SUBMARINE"

func TestPKCS7Padding(t *testing.T) {
	in := YELLOWSUBMARINE
	want := "YELLOW SUBMARINE\x04\x04\x04\x04"
	got := PKCSPadString(in, 20)
	if got != want {
		t.Errorf("PKCSPadding(%q) == %q, want %q", in, got, want)
	}
}

func TestRemovePKCS7Padding(t *testing.T) {
	want := YELLOWSUBMARINE
	in := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	got := RemovePKCSPadding(in)
	if string(got) != want {
		t.Errorf("RemovePKCSPadding(%q) == %q, want %q", in, got, want)
	}
}

func TestEncryptECB(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	c, err := Encrypt(ECB, PlainText{plaintext: []byte(FunkyMusic), key: key})
	if err != nil {
		t.Errorf("EncryptECB(%q) threw an error: %s", FunkyMusic, err)
	}
	got, err := Decrypt(ECB, c)
	if err != nil {
		t.Errorf("DecryptECB(%q) threw an error: %s", FunkyMusic, err)
	}
	if string(got.plaintext) != FunkyMusic {
		t.Errorf("DecryptECB(%q) == %q, want %q", FunkyMusic, got.plaintext, FunkyMusic)
	}
}

func TestEncryptAESCBC(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	in := "NADAVRECCAAAA"
	iv := RepeatBytesToLegnth([]byte{0}, aes.BlockSize)
	want := string(FlexibleXor([]byte(in), iv))
	c, err := Encrypt(CBC, PlainText{plaintext: []byte(in), key: key, iv: iv})
	if err != nil {
		t.Errorf("encryptCBC(%q) threw an error: %s", in, err)
	}
	in2 := EncryptedText{ciphertext: []byte(c.ciphertext), key: key, iv: iv}
	got, err := Decrypt(CBC, in2)
	if err != nil {
		t.Errorf("decryptCBC(%q) threw an error: %s", in2, err)
	}
	if string(got.plaintext) != want {
		t.Errorf("decryptCBC(%q) == %q, want %q", in, string(got.plaintext), want)
	}
}

func TestEncryptCBC(t *testing.T) {
	filename := "challenges/challenge10.txt"
	decoded, err := ReadBase64File(filename)
	if err != nil {
		t.Errorf("ReadBase64File(%q) threw an error: %s", filename, err)
	}
	key := []byte("YELLOW SUBMARINE")
	in := EncryptedText{key: key, ciphertext: decoded, iv: RepeatBytesToLegnth([]byte{0}, aes.BlockSize)}
	got, err := decryptCBC(in)
	if err != nil {
		t.Errorf("decryptCBC(%q) threw an error: %s", in, err)
	}
	if string(got.plaintext) != FunkyMusic {
		t.Errorf("encryptCBC(%q) == %q, want %q", in, got, FunkyMusic)
	}
}

func TestEncryptionOracle(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	mode := ECB
	if rand.Float64() < float64(0.5) {
		mode = CBC
	}
	plaintext, err := EncryptionOracle([]byte(FunkyMusic), mode)
	if err != nil {
		t.Errorf("EncryptionOracle(%q) threw an error: %s", FunkyMusic, err)
	}
	guessed := GuessAESMode(plaintext)
	if guessed != mode {
		t.Errorf("GuessAESMode returned incorrect mode: got %d, want %d", guessed, mode)
	}
}

var Base64EncodedString = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

func TestDecryptOracle(t *testing.T) {
	parsed, err := ParseBase64(Base64EncodedString)
	if err != nil {
		t.Errorf("ParseBase64(%q) threw an error: %s", Base64EncodedString, err)
	}
	f := getEncryptionFunction(parsed)
	plaintext, err := DecryptOracle(f)
	if err != nil {
		t.Errorf("DecryptOracle(f) threw an error: %s", err)
	}
	want := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
	if string(plaintext) != want {
		t.Errorf("DecryptOracle(f) returned incorrect plaintext: got:\n %q \n want \n %q", plaintext, want)
	}
}
func TestParseCookie(t *testing.T) {
	in := "foo=bar&baz=qux&zap=zazzle"
	got := ParseCookie(in)
	if got["foo"] != "bar" || got["baz"] != "qux" || got["zap"] != "zazzle" {
		t.Errorf("ParseCookie gave some bad results: %s", got)
	}
}

func TestEncryptProfile(t *testing.T) {
	email := []byte("foo@bar.com")
	enc, err := EncryptedProfileFor(email)
	if err != nil {
		t.Errorf("Encrypt threw an error: %s", err)
	}
	role, err := Decrypt(ECB, enc)
	if err != nil {
		t.Errorf("Decrypt threw an error: %s", err)
	}
	cookie := ParseCookie(string(role.plaintext))
	if cookie["role"] != "user" || cookie["email"] != string(email) || cookie["uid"] != "10" {
		t.Errorf("ParseCookie for %s returned: %s", email, role.plaintext)
	}
}

func TestCreateAdminProfile(t *testing.T) {
	email := "foo@bar.com"
	enc, err := BuildAdminProfile(email)

	if err != nil {
		t.Errorf("BuildAdminProfile threw an error: %s", err)
		return
	}
	role, err := Decrypt(ECB, enc)
	if err != nil {
		t.Errorf("Decrypt threw an error: %s", err)
		return
	}
	cookie := ParseCookie(string(role.plaintext))

	if cookie["role"] != "admin" {
		t.Errorf(string(role.plaintext))
		t.Errorf("BuildAdminProfile did not return an admin profile, got %s ", cookie["role"])
	}
}

func TestDecryptOracleHarder(t *testing.T) {
	parsed, err := ParseBase64(Base64EncodedString)
	if err != nil {
		t.Errorf("ParseBase64(%q) threw an error: %s", Base64EncodedString, err)
		return
	}
	f := getEncryptionFunctionHarder(parsed)
	plaintext, err := DecryptOracle(f)
	if err != nil {
		t.Errorf("DecryptOracleHarder(f) threw an error: %s", err)
		return
	}
	want := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
	if string(plaintext) != want {
		t.Errorf("DecryptOracleHarder(f) returned incorrect plaintext: got:\n %q \n want \n %q", plaintext, want)
	}
}
