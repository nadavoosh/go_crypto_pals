package cryptopals

import (
	// "bytes"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mathRand "math/rand"
	"regexp"
	"strings"
	"testing"
	"time"
)

const mersenneNumberBytes = 4 // each mersenne number is 32 bits long, which is 4 bytes of keystream

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
	d := PlainText{plaintext: []byte(plaintext), CryptoMaterial: CryptoMaterial{key: FixedKey, iv: GenerateKey()}}
	return Encrypt(CBC, d)
}

func mersenneEncrypt(plaintext []byte, seed uint16) (EncryptedText, error) {
	keyByteArray := make([]byte, 2)
	binary.BigEndian.PutUint16(keyByteArray, seed)

	d := PlainText{
		plaintext: plaintext,
		CryptoMaterial: CryptoMaterial{key: keyByteArray},
	}
	return Encrypt(MT, d)
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
		ciphertext:     cipherterxt,
		CryptoMaterial: CryptoMaterial{key: key, nonce: nonce},
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
		plaintext:      []byte(want),
		CryptoMaterial: CryptoMaterial{key: key, nonce: nonce},
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
	keystreamGuess := []byte{61, 119, 199, 221, 251, 12, 179, 47, 28, 48, 171, 47, 152, 235, 153, 236, 113, 47, 144, 28, 151, 200, 54, 228, 104, 190, 165, 111, 120, 237, 239, 125, 179, 228, 122, 201, 172, 60}
	for _, plaintextLine := range lines {
		decoded, err := ParseBase64(plaintextLine)
		if err != nil {
			t.Errorf("ReadBase64File(%q) threw an error: %s", filename, err)
			return
		}
		d := PlainText{
			plaintext:      decoded,
			CryptoMaterial: CryptoMaterial{key: key, nonce: nonce},
		}
		c, err := Encrypt(CTC, d)
		if err != nil {
			t.Errorf("Encrypt(%q) threw an error: %s", filename, err)
			return
		}
		l := min(len(decoded), len(keystreamGuess))
		plaintextBytes := FlexibleXor(keystreamGuess[:l], c.ciphertext)
		fmt.Println(plaintextBytes[l:])
		fmt.Println(string(plaintextBytes))
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
	rawCiphertexts := [][]byte{}
	minLen := 100000
	for _, plaintextLine := range lines {
		decoded, err := ParseBase64(plaintextLine)
		if err != nil {
			t.Errorf("ParseBase64(%q) threw an error: %s", filename, err)
			return
		}
		actual = append(actual, decoded...)
		d := PlainText{
			plaintext:      decoded,
			CryptoMaterial: CryptoMaterial{key: key, nonce: nonce},
		}
		c, err := Encrypt(CTC, d)
		if err != nil {
			t.Errorf("Encrypt(%q) threw an error: %s", filename, err)
			return
		}
		if len(c.ciphertext) < minLen {
			minLen = len(c.ciphertext)
		}
		rawCiphertexts = append(rawCiphertexts, c.ciphertext)
	}
	ciphertexts := []byte{}
	for _, ciphertext := range rawCiphertexts {
		ciphertexts = append(ciphertexts, ciphertext[:minLen]...)
	}
	got, err := DecryptRepeatingKeyXorWithKeysize(ciphertexts, minLen)
	if err != nil {
		t.Errorf("DecryptRepeatingKeyXorWithKeysize threw an error: %s", err)
		return
	}
	for i, line := range lines {
		actualBytes, err := ParseBase64(line)
		if err != nil {
			t.Errorf("ParseBase64(%q) threw an error: %s", filename, err)
			return
		}

		// Make a Regex to say we only want letters and numbers
		reg, err := regexp.Compile("[^a-zA-Z0-9]+")
		if err != nil {
			t.Errorf("%v", err)
		}

		decryptedString := strings.ToLower(reg.ReplaceAllString(string(got.plaintext[minLen*i:minLen*(i+1)]), ""))
		actualTrimmedString := strings.ToLower(reg.ReplaceAllString(string(actualBytes[:minLen]), ""))

		if decryptedString != actualTrimmedString {
			t.Errorf("DecryptRepeatingKeyXorWithKeysize didn't work for block %v: \n%s\n%s", i, decryptedString, actualTrimmedString)
			return
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
		return
	}
	m.Seed(523)
	seededSum := 0
	for i := 0; i < 123; i++ {
		seededSum += int(m.Uint32())
	}
	if seededSum != 282554711866 {
		t.Errorf("MersenneTwister seeded sum isn't right: %v\n", seededSum)
		return
	}
}

func TestDiscoverSeed(t *testing.T) {
	t.Skip("this test contians a lot of randomized waiting, by design.")
	// run this test with `-timeout 0`
	m := NewMersenneTwister()
	mathRand.Seed(time.Now().Unix())
	waitAtLeast := int32(40)
	waitAtMost := int32(1000)
	wait := mathRand.Int31n(waitAtMost-waitAtLeast) + waitAtLeast
	fmt.Printf("Waiting %v seconds...\n", wait)
	time.Sleep(time.Duration(wait) * time.Second)
	tt := time.Now().Unix()
	m.Seed(int(tt))
	wait2 := mathRand.Int31n(waitAtMost-waitAtLeast) + waitAtLeast
	fmt.Printf("Waiting another %v seconds...\n", wait2)
	time.Sleep(time.Duration(wait2) * time.Second)
	out := m.Uint32()

	// now guess:
	var guessedRight bool
	tGuess := int(time.Now().Unix())
	for i := -(int(waitAtMost))*2 - 10; i < -int(waitAtLeast); i++ {
		m.Seed(tGuess + i)
		if m.Uint32() == out {
			guessedRight = true
			fmt.Printf("The seed was %v, which was %v seconds ago\n", tGuess+i, -i)
			break
		}
	}
	if !guessedRight {
		t.Errorf("Couldn't figure out the seed. Should have found %v", tt)
		return
	}
}

func TestCloneMT19937(t *testing.T) {
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
			return
		}
	}
}
func TestMT19937Encryption(t *testing.T) {
	key := GenerateKey()
	original := []byte("YELLOWSUBMARINE")
	d := PlainText{
		plaintext:      original,
		CryptoMaterial: CryptoMaterial{key: key},
	}
	c, err := Encrypt(MT, d)
	if err != nil {
		t.Errorf("Encrypt threw an error: %s", err)
		return
	}

	p, err := Decrypt(MT, c)
	if err != nil {
		t.Errorf("Decrypt threw an error: %s", err)
		return
	}

	if string(p.plaintext) != string(original) {
		t.Errorf("Decrypt didn't work. Got\n`%s` instead of \n`%s`\n", p.plaintext, original)
		return
	}
}

func TestBreakMT19937Encryption(t *testing.T) {
	const MersenneSeedSpace = 65536
	base := bytes.Repeat(ByteA, 14)
	randomBytes := make([]byte, mathRand.Intn(5)+5)
	_, err := rand.Read(randomBytes)
	if err != nil {
		t.Errorf("rand.Read threw an error: %s", err)
		return
	}

	c, err := mersenneEncrypt(append(randomBytes, base...), uint16(mathRand.Intn(MersenneSeedSpace)))
	if err != nil {
		t.Errorf("encryptMT threw an error: %s", err)
		return
	}

	randomByteCount := len(c.ciphertext) - len(base)
	merseeneValueSlice := FlexibleXor(c.ciphertext[randomByteCount:len(c.ciphertext)], base)
	var success bool

	// try all the possible keys until we find one that generates the known sequence in merseeneValueSlice
	for i := 0; i < MersenneSeedSpace; i++ {
		m := NewMersenneTwister()
		m.Seed(i)

		size := len(c.ciphertext)/mersenneStreamBlockSize
		if len(c.ciphertext) % mersenneStreamBlockSize > 0 {
			size++
		}

		comparison := make([]byte, size*mersenneStreamBlockSize)
		numbersNeeded := size * mersenneStreamBlockSize / mersenneNumberBytes

		for i := 0; i < numbersNeeded; i++ {
			binary.LittleEndian.PutUint32(comparison[(i*mersenneNumberBytes):], m.Uint32())
		}
		if string(merseeneValueSlice) == string(comparison[randomByteCount:len(c.ciphertext)]) {
			success = true
			break
		}
	}
	if !success {
		t.Errorf("Key not found. Should have been: %s\n", c.CryptoMaterial.key)
	}
}

func tokenOracle() (EncryptedText, error) {
	plaintext := bytes.Repeat(ByteA, mathRand.Intn(20)+4)
	return mersenneEncrypt(plaintext, uint16(time.Now().Unix()))
}

func isTokenForRecentTime(token string) (bool, error) {
	now := int(time.Now().Unix())
	sampleText := bytes.Repeat(ByteA, len(token)) // we know the oracle is just encrypting byteA repeated
	window := 10 * 60 // check the last 10 minutes
	for i := now; i > now - window; i-- {
		c, err := mersenneEncrypt(sampleText, uint16(i))
		if err != nil {
			return false, err
		}
		if string(c.ciphertext) == token {
			return true, nil
		}
	}
	return false, nil
}

func TestGeneratePasswordResetToken(t *testing.T) {
	token, err := tokenOracle()
	if err != nil {
		t.Errorf("tokenOracle threw an error: %s", err)
		return
	}
	found, err := isTokenForRecentTime(string(token.ciphertext))
	if err != nil {
		t.Errorf("isTokenForRecentTime threw an error: %s", err)
		return
	}

	if !found {
		t.Errorf("Password Reset Token not identified.")
	}
}
