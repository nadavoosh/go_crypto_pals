package cryptopals

import (
	// "math/rand"
	"testing"
)

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
	decryptAndValidatePadding := getValidationFnForOracle(d.key)
	valid, err := decryptAndValidatePadding(d.ciphertext, d.iv)
	if err != nil {
		t.Errorf("decryptAndValidatePadding threw an error: %s", err)
		return
	}
	if !valid {
		t.Errorf("decryptAndValidatePadding failed to validate: %s", d.ciphertext)
	}
}

func TestCBCPaddingOracle(t *testing.T) {
	encrypt, err := padAndEncryptFromSet()
	if err != nil {
		t.Errorf("padAndEncrypt(f) threw an error: %s", err)
		return
	}
	oracle := CBCPaddingOracle{iv: encrypt.iv, ciphertext: encrypt.ciphertext, validationFn: getValidationFnForOracle(encrypt.key)}
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

func TestCTRCipher(t *testing.T) {
	cipherterxt, err := ParseBase64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	if err != nil {
		t.Errorf("ParseBase64 threw an error: %s", err)
		return
	}
	key := []byte("YELLOW SUBMARINE")
	nonce := int64(0)
	e := EncryptedText{
		ciphertext: cipherterxt,
		key:        key,
		nonce:      nonce,
	}
	p, err := Decrypt(CTC, e)
	if err != nil {
		t.Errorf("Decrypt threw an error: %s", err)
		return
	}
	want := "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
	if string(p.plaintext) != want {
		t.Errorf("Decrypt returned: %s, want %s", p.plaintext, want)
		return
	}
	d := PlainText{
		plaintext: []byte(want),
		key:       key,
		nonce:     nonce,
	}
	c, err := Encrypt(CTC, d)
	if err != nil {
		t.Errorf("Encrypt threw an error: %s", err)
		return
	}
	if string(c.ciphertext) != string(cipherterxt) {
		t.Errorf("Encrypt returned: %s, want %s", c.ciphertext, cipherterxt)
		return
	}

}
