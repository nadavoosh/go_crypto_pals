package cryptopals

import (
	"crypto/aes"
	"math/rand"
	"testing"
	"time"
)

func TestPKCS7Padding(t *testing.T) {
	in := "YELLOW SUBMARINE"
	want := "YELLOW SUBMARINE\x04\x04\x04\x04"
	got := PKCSPadString(in, 20)
	if got != want {
		t.Errorf("PKCSPadding(%q) == %q, want %q", in, got, want)
	}
}

func TestRemovePKCS7Padding(t *testing.T) {
	want := "YELLOW SUBMARINE"
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

func TestencryptCBC(t *testing.T) {
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
func TestDecryptOracle(t *testing.T) {
	prepend := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	parsed, err := ParseBase64(prepend)
	if err != nil {
		t.Errorf("ParseBase64(%q) threw an error: %s", prepend, err)
	}

	f := GetEncryptionFunction(parsed)
	plaintext, err := DecryptOracle(f)
	if err != nil {
		t.Errorf("DecryptOracle(f) threw an error: %s", err)
	}
	want := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
	if string(plaintext) != want {
		t.Errorf("DecryptOracle(f) returned incorrect plaintext: got:\n %q \n want \n %q", plaintext, want)
	}
}
