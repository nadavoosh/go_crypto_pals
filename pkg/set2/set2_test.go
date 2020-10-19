package set2

import (
	"crypto/aes"
	"math/rand"
	"testing"
	"time"

	"github.com/nadavoosh/go_crypto_pals/pkg/padding"
	"github.com/nadavoosh/go_crypto_pals/pkg/pals"
	"github.com/nadavoosh/go_crypto_pals/pkg/set1"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

func TestPKCS7Padding(t *testing.T) {
	in := YELLOWSUBMARINE
	want := "YELLOW SUBMARINE\x04\x04\x04\x04"
	got := padding.PKCSPadString(in, 20)
	if got != want {
		t.Errorf("padding.PKCSPadding(%q) == %q, want %q", in, got, want)
	}
}

func TestRemovePKCS7Padding(t *testing.T) {
	want := YELLOWSUBMARINE
	in := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	got := padding.RemovePKCSPadding(in)
	if string(got) != want {
		t.Errorf("padding.RemovePKCSPadding(%q) == %q, want %q", in, got, want)
	}
}

func TestEncryptECB(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	c, err := pals.AES_ECB{PlainText: pals.PlainText{Plaintext: []byte(set1.FunkyMusicPadded), Key: key}}.Encrypt()
	if err != nil {
		t.Errorf("EncryptECB(%q) threw an error: %s", set1.FunkyMusicPadded, err)
	}
	cPrime := pals.AES_ECB{EncryptedText: c}
	got, err := cPrime.Decrypt()
	if err != nil {
		t.Errorf("DecryptECB(%q) threw an error: %s", set1.FunkyMusicPadded, err)
	}
	if string(got.Plaintext) != set1.FunkyMusicPadded {
		t.Errorf("DecryptECB(%q) == %q, want %q", set1.FunkyMusicPadded, got.Plaintext, set1.FunkyMusicPadded)
	}
}

func TestEncryptAESCBC(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	in := "NADAVRECCAAAA"
	IV := pals.RepeatBytesToLegnth([]byte{1}, aes.BlockSize)
	c, err := pals.AES_CBC{PlainText: pals.PlainText{Plaintext: []byte(in), Key: key, IV: IV}}.Encrypt()
	if err != nil {
		t.Errorf("encryptCBC(%q) threw an error: %s", in, err)
	}
	in2 := pals.EncryptedText{Ciphertext: []byte(c.Ciphertext), Key: key, IV: IV}
	got, err := pals.AES_CBC{EncryptedText: in2}.Decrypt()
	if err != nil {
		t.Errorf("DecryptCBC(%v) threw an error: %s", in2, err)
	}
	if string(got.Plaintext) != in {
		t.Errorf("DecryptCBC(%q) == %q, want %q", in, string(got.Plaintext), in)
	}
}

func TestEncryptCBC(t *testing.T) {
	filename := "../../challenges/challenge10.txt"
	decoded, err := utils.ReadBase64File(filename)
	if err != nil {
		t.Errorf("ReadBase64File(%q) threw an error: %s", filename, err)
	}
	Key := []byte("YELLOW SUBMARINE")
	in := pals.EncryptedText{Ciphertext: decoded, Key: Key, IV: pals.RepeatBytesToLegnth([]byte{0}, aes.BlockSize)}

	got, err := pals.AES_CBC{EncryptedText: in}.Decrypt()
	if err != nil {
		t.Errorf("DecryptCBC(%v) threw an error: %s", in, err)
	}
	if !pals.TestEq(got.Plaintext, padding.RemovePKCSPadding([]byte(set1.FunkyMusicPadded))) {
		t.Errorf("encryptCBC(input) is %v, want %q", string(got.Plaintext), set1.FunkyMusicPadded)
	}
}

func TestNewEncryptor(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	mode := pals.ECB
	if rand.Float64() < float64(0.5) {
		mode = pals.CBC
	}
	e, err := pals.NewEncryptor([]byte(set1.FunkyMusicPadded), mode)
	if err != nil {
		t.Errorf("NewEncryptor(%q) threw an error: %s", set1.FunkyMusicPadded, err)
	}
	Plaintext, err := e.Encrypt()
	if err != nil {
		t.Errorf("NewEncryptor.Encrypt(%q) threw an error: %s", set1.FunkyMusicPadded, err)
	}
	guessed := pals.GuessAESMode(Plaintext)
	if guessed != mode {
		t.Errorf("GuessAESMode returned incorrect mode: got %v, want %v", guessed, mode)
	}
}

var Base64EncodedString = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

func TestDecryptOracle(t *testing.T) {
	parsed, err := utils.ParseBase64(Base64EncodedString)
	if err != nil {
		t.Errorf("ParseBase64(%q) threw an error: %s", Base64EncodedString, err)
	}
	oracle := pals.EncryptionOracle{Encrypt: appendAndEncrypt(parsed), Mode: pals.ECBAppend}
	Plaintext, err := oracle.Decrypt()
	if err != nil {
		t.Errorf("DecryptOracle(f) threw an error: %s", err)
	}
	want := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
	if string(Plaintext) != want {
		t.Errorf("DecryptOracle(f) returned incorrect Plaintext: got:\n %q \n want \n %q", Plaintext, want)
	}
}
func TestParseCookie(t *testing.T) {
	in := "foo=bar&baz=qux&zap=zazzle"
	got := parseCookie(in)
	if got["foo"] != "bar" || got["baz"] != "qux" || got["zap"] != "zazzle" {
		t.Errorf("ParseCookie gave some bad results: %s", got)
	}
}

func TestEncryptProfile(t *testing.T) {
	email := []byte("foo@bar.com")
	enc, err := encryptedProfileFor(email)
	if err != nil {
		t.Errorf("Encrypt threw an error: %s", err)
	}
	encPrime := pals.AES_ECB{EncryptedText: enc}
	role, err := encPrime.Decrypt()
	if err != nil {
		t.Errorf("Decrypt threw an error: %s", err)
	}
	cookie := parseCookie(string(role.Plaintext))
	if cookie["role"] != "user" || cookie["email"] != string(email) || cookie["uid"] != "10" {
		t.Errorf("ParseCookie for %s returned: %s", email, role.Plaintext)
	}
}

func TestCreateAdminProfile(t *testing.T) {
	email := "foo@bar.com"
	enc, err := buildAdminProfile(email)

	if err != nil {
		t.Errorf("BuildAdminProfile threw an error: %s", err)
		return
	}
	encPrime := pals.AES_ECB{EncryptedText: enc}
	role, err := encPrime.Decrypt()
	if err != nil {
		t.Errorf("Decrypt threw an error: %s", err)
		return
	}
	cookie := parseCookie(string(role.Plaintext))

	if cookie["role"] != "admin" {
		t.Errorf(string(role.Plaintext))
		t.Errorf("BuildAdminProfile did not return an admin profile, got %s ", cookie["role"])
	}
}

func TestDecryptOracleHarder(t *testing.T) {
	parsed, err := utils.ParseBase64(Base64EncodedString)
	if err != nil {
		t.Errorf("ParseBase64(%q) threw an error: %s", Base64EncodedString, err)
		return
	}
	oracle := pals.EncryptionOracle{Encrypt: prependAndAppendAndEncrypt(parsed), Mode: pals.ECBAppend}
	Plaintext, err := oracle.Decrypt()
	if err != nil {
		t.Errorf("DecryptOracleHarder(f) threw an error: %s", err)
		return
	}
	want := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
	if string(Plaintext) != want {
		t.Errorf("DecryptOracleHarder(f) returned incorrect Plaintext: got:\n %q \n want \n %q", Plaintext, want)
	}
}

func TestPaddingValidation(t *testing.T) {
	valid := []byte("ICE ICE BABY\x04\x04\x04\x04")
	if !padding.ValidatePKCS(valid) {
		t.Errorf("ValidatePKCS incorrectly invalidated first string: %s", valid)
	}
	invalid1 := []byte("ICE ICE BABY\x05\x05\x05\x05")
	if padding.ValidatePKCS(invalid1) {
		t.Errorf("ValidatePKCS incorrectly validated second string: %s", invalid1)
	}
	invalid2 := []byte("ICE ICE BABY\x01\x02\x03\x04")
	if padding.ValidatePKCS(invalid2) {
		t.Errorf("ValidatePKCS incorrectly validated third string: %s", invalid2)
	}
}

func TestAdminEscape(t *testing.T) {
	in := []byte(";admin=true;asdf=asdf")
	userData, err := pals.EncryptUserData(in)
	if err != nil {
		t.Errorf("EncryptUserData(f) threw an error: %s", err)
		return
	}
	admin, err := pals.DetectAdminString(userData)
	if err != nil {
		t.Errorf("DetectAdminString(f) threw an error: %s", err)
		return
	}
	if admin {
		t.Errorf("DetectAdminString incorrectly detected the admin string for: %s", in)
	}
}
func TestFlipBitForAdmin(t *testing.T) {
	in := pals.AByteBlock()
	flipped := pals.FlipBitsToHide(pals.FlipBitsToHide(in))
	if !pals.TestEq(flipped, in) {
		t.Errorf("FlipBitForAdmin didn't undo itself: got %s, want %s", flipped, in)
	}
}

func TestCBCBitflipping(t *testing.T) {
	in := []byte(";admin=true")
	flipped := pals.FlipBitsToHide(in)
	userData, err := pals.EncryptUserData(append(flipped, flipped...))
	if err != nil {
		t.Errorf("EncryptUserData threw an error: %s", err)
		return
	}
	b, err := pals.ModifyCiphertextForAdmin(userData.Ciphertext)
	if err != nil {
		t.Errorf("ModifyCiphertextForAdmin threw an error: %s", err)
		return
	}
	c := userData
	c.Ciphertext = b
	admin, err := pals.DetectAdminString(c)
	if err != nil {
		t.Errorf("DetectAdminString(f) threw an error: %s", err)
		return
	}
	if !admin {
		t.Errorf("DetectAdminString incorrectly missed the admin string for: %s", in)
	}
}
