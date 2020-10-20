package sets

import (
	"crypto/aes"
	"math/rand"
	"testing"
	"time"

	"github.com/nadavoosh/go_crypto_pals/pkg/padding"
	"github.com/nadavoosh/go_crypto_pals/pkg/pals"
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
	c, err := pals.NewAESECB([]byte(FunkyMusicPadded)).Encrypt(key)
	if err != nil {
		t.Errorf("EncryptECB(%q) threw an error: %s", FunkyMusicPadded, err)
	}
	cPrime := pals.AES_ECB{Ciphertext: c, Padding: padding.PKCS}
	got, err := cPrime.Decrypt(key)
	if err != nil {
		t.Errorf("DecryptECB(%q) threw an error: %s", FunkyMusicPadded, err)
	}
	if string(got) != FunkyMusicPadded {
		t.Errorf("DecryptECB(%q) == %q, want %q", FunkyMusicPadded, got, FunkyMusicPadded)
	}
}

func TestEncryptAESCBC(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	in := "NADAVRECCAAAA"
	IV := pals.RepeatBytesToLegnth([]byte{1}, aes.BlockSize)
	a := pals.AES_CBC{Plaintext: []byte(in), IV: IV}
	c, err := a.Encrypt(key)
	if err != nil {
		t.Errorf("encryptCBC(%q) threw an error: %s", in, err)
	}
	b := pals.AES_CBC{Ciphertext: []byte(c), IV: IV}
	got, err := b.Decrypt(key)
	if err != nil {
		t.Errorf("DecryptCBC threw an error: %s", err)
	}
	if string(got) != in {
		t.Errorf("DecryptCBC(%q) == %q, want %q", in, string(got), in)
	}
}

func TestEncryptCBC(t *testing.T) {
	filename := "../../challenges/challenge10.txt"
	decoded, err := utils.ReadBase64File(filename)
	if err != nil {
		t.Errorf("ReadBase64File(%q) threw an error: %s", filename, err)
	}
	key := []byte("YELLOW SUBMARINE")
	a := pals.AES_CBC{Ciphertext: decoded, IV: pals.RepeatBytesToLegnth([]byte{0}, aes.BlockSize)}
	got, err := a.Decrypt(key)
	if err != nil {
		t.Errorf("DecryptCBC threw an error: %s", err)
	}
	if !pals.TestEq(got, padding.RemovePKCSPadding([]byte(FunkyMusicPadded))) {
		t.Errorf("encryptCBC(input) is %v, want %q", string(got), FunkyMusicPadded)
	}
}

func TestNewEncryptor(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	mode := pals.ECB
	if rand.Float64() < float64(0.5) {
		mode = pals.CBC
	}
	e, err := pals.NewEncryptor([]byte(FunkyMusicPadded), mode)
	if err != nil {
		t.Errorf("NewEncryptor(%q) threw an error: %s", FunkyMusicPadded, err)
	}
	Plaintext, err := e.Encrypt()
	if err != nil {
		t.Errorf("NewEncryptor.Encrypt(%q) threw an error: %s", FunkyMusicPadded, err)
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
	encPrime := pals.AES_ECB{Ciphertext: enc, Padding: padding.PKCS}
	role, err := encPrime.Decrypt(utils.FixedKey)
	if err != nil {
		t.Errorf("Decrypt threw an error: %s", err)
	}
	cookie := parseCookie(string(role))
	if cookie["role"] != "user" || cookie["email"] != string(email) || cookie["uid"] != "10" {
		t.Errorf("parseCookie for %s returned: %s", email, cookie)
	}
}

func TestCreateAdminProfile(t *testing.T) {
	email := "foo@bar.com"
	enc, err := buildAdminProfile(email)

	if err != nil {
		t.Errorf("BuildAdminProfile threw an error: %s", err)
		return
	}
	encPrime := pals.AES_ECB{Ciphertext: enc, Padding: padding.PKCS}
	role, err := encPrime.Decrypt(utils.FixedKey)
	if err != nil {
		t.Errorf("Decrypt threw an error: %s", err)
		return
	}
	cookie := parseCookie(string(role))

	if cookie["role"] != "admin" {
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
	userData, iv, err := encryptUserDataCBC(in)
	if err != nil {
		t.Errorf("EncryptUserData(f) threw an error: %s", err)
		return
	}
	admin, err := detectAdminStringCBC(userData, iv)
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
	flipped := flipBitsToHide(flipBitsToHide(in))
	if !pals.TestEq(flipped, in) {
		t.Errorf("FlipBitForAdmin didn't undo itself: got %s, want %s", flipped, in)
	}
}

func TestCBCBitflipping(t *testing.T) {
	in := []byte(";admin=true")
	flipped := flipBitsToHide(in)
	userData, iv, err := encryptUserDataCBC(append(flipped, flipped...))
	if err != nil {
		t.Errorf("EncryptUserData threw an error: %s", err)
		return
	}
	b, err := modifyCiphertextForAdmin(userData)
	if err != nil {
		t.Errorf("ModifyCiphertextForAdmin threw an error: %s", err)
		return
	}
	admin, err := detectAdminStringCBC(b, iv)
	if err != nil {
		t.Errorf("detectAdminStringCBC(f) threw an error: %s", err)
		return
	}
	if !admin {
		t.Errorf("DetectAdminString incorrectly missed the admin string for: %s", in)
	}
}
