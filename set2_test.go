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

func TestEncryptAESECB(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	c, err := EncryptAESECB(DecryptionResult{plaintext: []byte(FunkyMusic), key: key})
	if err != nil {
		t.Errorf("EncryptAESECB(%q) threw an error: %s", FunkyMusic, err)
	}
	got, err := DecryptAESECB(EncryptionResult{ciphertext: []byte(c.ciphertext), key: key})
	if err != nil {
		t.Errorf("DecryptAESECB(%q) threw an error: %s", FunkyMusic, err)
	}
	if string(got.plaintext) != FunkyMusic {
		t.Errorf("DecryptAESECB(%q) == %q, want %q", FunkyMusic, got.plaintext, FunkyMusic)
	}
}

func TestEncryptAESCBC(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	in := "NADAVRECCAAAA"
	iv := RepeatBytesToLegnth([]byte{0}, aes.BlockSize)
	want := string(FlexibleXor([]byte(in), iv))
	c, err := EncryptCBCMode(DecryptionResult{plaintext: []byte(in), key: key}, iv)
	if err != nil {
		t.Errorf("EncryptCBCMode(%q) threw an error: %s", in, err)
	}
	in2 := EncryptionResult{ciphertext: []byte(c.ciphertext), key: key}
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
	in := EncryptionResult{key: key, ciphertext: decoded}
	iv := RepeatBytesToLegnth([]byte{0}, aes.BlockSize)
	got, err := DecryptCBCMode(in, iv)
	if err != nil {
		t.Errorf("DecryptCBCMode(%q) threw an error: %s", in, err)
	}
	if string(got.plaintext) != FunkyMusic {
		t.Errorf("EncryptCBCMode(%q) == %q, want %q", in, got, FunkyMusic)
	}
}
