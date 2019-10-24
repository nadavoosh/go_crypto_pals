package cryptopals

import (
	"fmt"
	"math/rand"
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestBreakCTRWithGuessing(t *testing.T) {
	t.Skip("Guessing challenge is meant to be run interactively & iteratively.")
	filename := "challenges/challenge19.txt"
	lines, err := ScanFile(filename)
	if err != nil {
		t.Errorf("ScanFile threw an error: %s", err)
		return
	}
	nonce := int64(0)
	// randomly generated:
	key := []byte{18, 39, 184, 124, 192, 76, 210, 222, 7, 118, 111, 129, 173, 147, 95, 187}
	// guessed iteratively by looking at what prints and finding one letter to try next:
	keystream_guess := []byte{61, 119, 199, 221, 251, 12, 179, 47, 28, 48, 171, 47, 152, 235, 153, 236, 113, 47, 144, 28, 151, 200, 54, 228, 104, 190, 165, 111, 120, 237, 239, 125, 179, 228, 122, 201, 172, 60}
	for _, plaintext_line := range lines {
		decoded, err := ParseBase64(plaintext_line)
		if err != nil {
			t.Errorf("ReadBase64File(%q) threw an error: %s", filename, err)
		}
		d := PlainText{
			plaintext: decoded,
			key:       key,
			nonce:     nonce,
		}
		c, err := Encrypt(CTC, d)
		if err != nil {
			t.Errorf("Encrypt(%q) threw an error: %s", filename, err)
		}
		l := min(len(decoded), len(keystream_guess))
		plaintext_bytes := FlexibleXor(keystream_guess[:l], c.ciphertext)
		fmt.Println(plaintext_bytes[l:])
		fmt.Println(string(plaintext_bytes))
	}
	return
}

func TestBreakCTRStatistically(t *testing.T) {
	filename := "challenges/challenge20.txt"
	lines, err := ScanFile(filename)
	if err != nil {
		t.Errorf("ScanFile threw an error: %s", err)
		return
	}
	actual := []byte{}
	nonce := int64(0)
	key := make([]byte, 32) /// long key
	_, err = rand.Read(key)
	raw_ciphertexts := [][]byte{}
	min_len := 100000
	for _, plaintext_line := range lines {
		decoded, err := ParseBase64(plaintext_line)
		actual = append(actual, decoded...)
		if err != nil {
			t.Errorf("ReadBase64File(%q) threw an error: %s", filename, err)
		}
		d := PlainText{
			plaintext: decoded,
			key:       key,
			nonce:     nonce,
		}
		c, err := Encrypt(CTC, d)
		if err != nil {
			t.Errorf("Encrypt(%q) threw an error: %s", filename, err)
		}
		if len(c.ciphertext) < min_len {
			min_len = len(c.ciphertext)
		}
		raw_ciphertexts = append(raw_ciphertexts, c.ciphertext)
	}
	ciphertexts := []byte{}
	for _, ciphertext := range raw_ciphertexts {
		ciphertexts = append(ciphertexts, ciphertext[:min_len]...)
	}
	got, err := DecryptRepeatingKeyXorWithKeysize(ciphertexts, min_len)
	if err != nil {
		t.Errorf("DecryptRepeatingKeyXorWithKeysize threw an error: %s", err)
	}
	if string(got.plaintext[:min_len]) != string(actual[:min_len]) { // this just tests that the first line decrypted correctly.
		t.Errorf("DecryptRepeatingKeyXorWithKeysize didn't work: \n%s\n%s", got.plaintext[:min_len], actual[:min_len])
	}
}
