package cryptopals

import (
	// "math/rand"
	"testing"
)

func padAndEncryptOracle() EncryptionFn {
	return func(_ []byte) (EncryptedText, error) {
		return padAndEncryptFromSet()
	}
}

func padAndEncryptFromSet() (EncryptedText, error) {
	strings := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	// plaintext, err := ParseBase64(strings[rand.Intn(len(strings)-1)])
	plaintext, err := ParseBase64(strings[0])
	if err != nil {
		return EncryptedText{}, err
	}
	d := PlainText{plaintext: []byte(plaintext), key: FixedKey, iv: GenerateKey()}
	return Encrypt(CBC, d)
}

func TestCBCPaddingValidation(t *testing.T) {
	d, err := padAndEncryptFromSet()
	if err != nil {
		t.Errorf("padAndEncrypt(f) threw an error: %s", err)
		return
	}
	valid, err := decryptAndValidatePadding(d)
	if err != nil {
		t.Errorf("decryptAndValidatePadding threw an error: %s", err)
		return
	}
	if !valid {
		t.Errorf("decryptAndValidatePadding failed to validate: %s", d.ciphertext)
	}
}

func TestCBCPaddingOracle(t *testing.T) {
	oracle := EncryptionOracle{encrypt: padAndEncryptOracle(), mode: CBCPadding}
	res, err := oracle.Decrypt()
	if err != nil {
		t.Errorf("oracle.Decrypt(f) threw an error: %s", err)
		return
	}
	want := "000000Now that the party is jumping"
	if string(res) != want {
		t.Errorf("oracle.Decrypt returned: %s, want %s", res, want)
	}
}
