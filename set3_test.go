package cryptopals

import (
	"fmt"
	mathRand "math/rand"
	"regexp"
	"strings"
	"testing"
	"time"
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
	key := GenerateKey()
	raw_ciphertexts := [][]byte{}
	min_len := 100000
	for _, plaintext_line := range lines {
		decoded, err := ParseBase64(plaintext_line)
		if err != nil {
			t.Errorf("ParseBase64(%q) threw an error: %s", filename, err)
		}
		actual = append(actual, decoded...)
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
	for i, line := range lines {
		actual_bytes, err := ParseBase64(line)
		if err != nil {
			t.Errorf("ParseBase64(%q) threw an error: %s", filename, err)
		}

		// Make a Regex to say we only want letters and numbers
		reg, err := regexp.Compile("[^a-zA-Z0-9]+")
		if err != nil {
			t.Errorf("%v", err)
		}

		decrypted_string := strings.ToLower(reg.ReplaceAllString(string(got.plaintext[min_len*i:min_len*(i+1)]), ""))
		actual_trimmed_string := strings.ToLower(reg.ReplaceAllString(string(actual_bytes[:min_len]), ""))

		if decrypted_string != actual_trimmed_string {
			t.Errorf("DecryptRepeatingKeyXorWithKeysize didn't work for block %v: \n%s\n%s", i, decrypted_string, actual_trimmed_string)
		}
	}
}

func TestImplementMersenneTwisterRNG(t *testing.T) {
	m := NewMersenneTwister()
	unseededSum := 0
	for i := 0; i < 123; i++ {
		unseededSum += int(m.Uint32())
	}
	if unseededSum != 268571260341 {
		t.Errorf("MersenneTwister unseeded sum isn't right: %v\n", unseededSum)
	}
	m.Seed(523)
	seededSum := 0
	for i := 0; i < 123; i++ {
		seededSum += int(m.Uint32())
	}
	if seededSum != 282554711866 {
		t.Errorf("MersenneTwister seeded sum isn't right: %v\n", seededSum)
	}
}

func TestDiscoverSeed(t *testing.T) {
	t.Skip()
	// run this test with `-timeout 0`
	m := NewMersenneTwister()
	mathRand.Seed(time.Now().Unix())
	wait_at_least := int32(40)
	wait_at_most := int32(1000)
	wait := mathRand.Int31n(wait_at_most-wait_at_least) + wait_at_least
	fmt.Printf("Waiting %v seconds...\n", wait)
	time.Sleep(time.Duration(wait) * time.Second)
	tt := time.Now().Unix()
	m.Seed(int(tt))
	wait2 := mathRand.Int31n(wait_at_most-wait_at_least) + wait_at_least
	fmt.Printf("Waiting another %v seconds...\n", wait2)
	time.Sleep(time.Duration(wait2) * time.Second)
	out := m.Uint32()
	// now guess:
	var guessed_right bool
	t_guess := int(time.Now().Unix())
	for i := -(int(wait_at_most))*2 - 10; i < -int(wait_at_least); i++ {
		m.Seed(t_guess + i)
		if m.Uint32() == out {
			guessed_right = true
			fmt.Printf("The seed was %v, which was %v seconds ago\n", t_guess+i, -i)
			break
		}
	}
	if !guessed_right {
		t.Errorf("Couldn't figure out the seed. Should have found %v", tt)
	}
}

func TestCloneMT199937(t *testing.T) {
	m := NewMersenneTwister()
	clone := NewMersenneTwister()
	m.Seed(int(time.Now().UnixNano()))
	const n = 624
	for i := 0; i < n; i++ {
		clone.state[i] = Untemper(m.Uint32())
	}
	// now the states are the same, but the clone.index is `notSeeded` and m.index is `n`.
	clone.index = n
	for i := 0; i < 2*n; i++ {
		if clone.Uint32() != m.Uint32() {
			t.Errorf("Clone incorrect somehow")
			break
		}
	}
}
