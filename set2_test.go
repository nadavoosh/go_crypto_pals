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
	c, err := EncryptECB(PlainText{plaintext: []byte(FunkyMusic), key: key})
	if err != nil {
		t.Errorf("EncryptECB(%q) threw an error: %s", FunkyMusic, err)
	}
	got, err := DecryptECB(c)
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
	c, err := EncryptCBC(PlainText{plaintext: []byte(in), key: key}, iv)
	if err != nil {
		t.Errorf("EncryptCBC(%q) threw an error: %s", in, err)
	}
	in2 := EncryptedText{ciphertext: []byte(c.ciphertext), key: key}
	got, err := DecryptCBC(in2, iv)
	if err != nil {
		t.Errorf("DecryptCBC(%q) threw an error: %s", in2, err)
	}
	if string(got.plaintext) != want {
		t.Errorf("DecryptCBC(%q) == %q, want %q", in, string(got.plaintext), want)
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
	got, err := DecryptCBC(in, iv)
	if err != nil {
		t.Errorf("DecryptCBC(%q) threw an error: %s", in, err)
	}
	if string(got.plaintext) != FunkyMusic {
		t.Errorf("EncryptCBC(%q) == %q, want %q", in, got, FunkyMusic)
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

func TestEncryptUnknownKeyWithPrepend(t *testing.T) {
	prepend := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	parsed, err := ParseBase64(prepend)
	if err != nil {
		t.Errorf("ParseBase64(%q) threw an error: %s", prepend, err)
	}
	plaintext, err := ByteByByteECBDecryption(parsed)
	if err != nil {
		t.Errorf("ByteByByteECBDecryption(%q) threw an error: %s", FunkyMusic, err)
	}
	want := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
	if string(plaintext) != want {
		t.Errorf("ByteByByteECBDecryption returned incorrect plaintext: got %s, want %s", plaintext, want)
	}
}