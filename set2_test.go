package cryptopals

import (
	"crypto/aes"
	"testing"
)

func TestPKCS7Padding(t *testing.T) {
	in := "YELLOW SUBMARINE"
	want := "YELLOW SUBMARINE\x04\x04\x04\x04"
	got := PKCSPadString(in, 20)
	if got != want {
		t.Errorf("PKCSPadding(%q) == %q, want %q", in, got, want)
	}
}

func TestEncryptAESECBMode(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	c, err := EncryptAESECBMode(PlainText{plaintext: []byte(FunkyMusic), key: key})
	if err != nil {
		t.Errorf("EncryptAESECBMode(%q) threw an error: %s", FunkyMusic, err)
	}
	got, err := DecryptAESECBMode(EncryptedText{ciphertext: []byte(c.ciphertext), key: key})
	if err != nil {
		t.Errorf("DecryptAESECBMode(%q) threw an error: %s", FunkyMusic, err)
	}
	if string(got.plaintext) != FunkyMusic {
		t.Errorf("DecryptAESECBMode(%q) == %q, want %q", FunkyMusic, got.plaintext, FunkyMusic)
	}
}

func TestEncryptAESCBC(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	in := "NADAVRECCAAAA"
	iv := RepeatBytesToLegnth([]byte{0}, aes.BlockSize)
	want := string(FlexibleXor([]byte(in), iv))
	c, err := EncryptCBCMode(PlainText{plaintext: []byte(in), key: key}, iv)
	if err != nil {
		t.Errorf("EncryptCBCMode(%q) threw an error: %s", in, err)
	}
	in2 := EncryptedText{ciphertext: []byte(c.ciphertext), key: key}
	got, err := DecryptCBCMode(in2, iv)
	if err != nil {
		t.Errorf("DecryptCBCMode(%q) threw an error: %s", in2, err)
	}
	if string(got.plaintext) != want {
		t.Errorf("DecryptCBCMode(%q) == %q, want %q", in, string(got.plaintext), want)
	}
}

func TestEncryptCBC(t *testing.T) {
	filename := "challenges/challenge10.txt"
	decoded, err := ReadBase64File(filename)
	if err != nil {
		t.Errorf("ReadBase64File(%q) threw an error: %s", filename, err)
	}
	key := []byte("YELLOW SUBMARINE")
	in := EncryptedText{key: key, ciphertext: decoded}
	iv := RepeatBytesToLegnth([]byte{0}, aes.BlockSize)
	got, err := DecryptCBCMode(in, iv)
	if err != nil {
		t.Errorf("DecryptCBCMode(%q) threw an error: %s", in, err)
	}
	if string(got.plaintext) != FunkyMusic {
		t.Errorf("EncryptCBCMode(%q) == %q, want %q", in, got, FunkyMusic)
	}
}

func TestEncryptionOracle(t *testing.T) {
	plaintext, err := EncryptionOracle([]byte(FunkyMusic))
	if err != nil {
		t.Errorf("EncryptionOracle(%q) threw an error: %s", FunkyMusic, err)
	}
	if GuessAESMode(plaintext) == "ECB Mode" {
		t.Errorf("GuessAESMode returned ECB Mode")
	}
}
