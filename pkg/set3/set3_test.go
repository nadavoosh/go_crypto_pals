package set3

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mathRand "math/rand"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nadavoosh/go_crypto_pals/pkg/mersenne"
	"github.com/nadavoosh/go_crypto_pals/pkg/pals"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

func TestCBCPaddingValidation(t *testing.T) {
	d, err := padAndEncryptFromSet()
	if err != nil {
		t.Errorf("padAndEncrypt(f) threw an error: %s", err)
		return
	}
	decryptAndValidatePadding := pals.GetValidationFnForOracle(d.Key)
	valid, err := decryptAndValidatePadding(d.Ciphertext, d.IV)
	if err != nil {
		t.Errorf("decryptAndValidatePadding threw an error: %s", err)
		return
	}
	if !valid {
		t.Errorf("decryptAndValidatePadding failed to validate: %s", d.Ciphertext)
	}
}

func TestCBCPaddingOracle(t *testing.T) {
	encrypt, err := padAndEncryptFromSet()
	if err != nil {
		t.Errorf("padAndEncrypt(f) threw an error: %s", err)
		return
	}
	oracle := pals.CBCPaddingOracle{IV: encrypt.IV, Ciphertext: encrypt.Ciphertext, ValidationFn: pals.GetValidationFnForOracle(encrypt.Key)}
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
	cipherterxt, err := utils.ParseBase64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	if err != nil {
		t.Errorf("ParseBase64 threw an error: %s", err)
		return
	}
	Key := []byte("YELLOW SUBMARINE")
	nonce := int64(0)
	e := pals.CTC{EncryptedText: pals.EncryptedText{
		Ciphertext:     cipherterxt,
		CryptoMaterial: pals.CryptoMaterial{Key: Key, Nonce: nonce},
	}}
	p, err := e.Decrypt()
	if err != nil {
		t.Errorf("Decrypt threw an error: %s", err)
		return
	}
	want := "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
	if string(p.Plaintext) != want {
		t.Errorf("Decrypt returned: %s, want %s", p.Plaintext, want)
		return
	}
	d := pals.CTC{PlainText: pals.PlainText{
		Plaintext:      []byte(want),
		CryptoMaterial: pals.CryptoMaterial{Key: Key, Nonce: nonce},
	}}
	c, err := d.Encrypt()
	if err != nil {
		t.Errorf("Encrypt threw an error: %s", err)
		return
	}
	if string(c.Ciphertext) != string(cipherterxt) {
		t.Errorf("Encrypt returned: %s, want %s", c.Ciphertext, cipherterxt)
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
	t.Skip("Guessing challenge is meant to be run interactIVely & iteratIVely.")
	filename := "../../challenges/challenge19.txt"
	lines, err := utils.ScanFile(filename)
	if err != nil {
		t.Errorf("ScanFile threw an error: %s", err)
		return
	}
	nonce := int64(0)
	// randomly generated:
	Key := []byte{18, 39, 184, 124, 192, 76, 210, 222, 7, 118, 111, 129, 173, 147, 95, 187}
	// guessed iteratIVely by looking at what prints and finding one letter to try next:
	KeystreamGuess := []byte{61, 119, 199, 221, 251, 12, 179, 47, 28, 48, 171, 47, 152, 235, 153, 236, 113, 47, 144, 28, 151, 200, 54, 228, 104, 190, 165, 111, 120, 237, 239, 125, 179, 228, 122, 201, 172, 60}
	for _, PlaintextLine := range lines {
		decoded, err := utils.ParseBase64(PlaintextLine)
		if err != nil {
			t.Errorf("ReadBase64File(%q) threw an error: %s", filename, err)
			return
		}
		d := pals.CTC{PlainText: pals.PlainText{
			Plaintext:      decoded,
			CryptoMaterial: pals.CryptoMaterial{Key: Key, Nonce: nonce},
		}}
		c, err := d.Encrypt()
		if err != nil {
			t.Errorf("Encrypt(%q) threw an error: %s", filename, err)
			return
		}
		l := min(len(decoded), len(KeystreamGuess))
		PlaintextBytes := utils.FlexibleXor(KeystreamGuess[:l], c.Ciphertext)
		fmt.Println(PlaintextBytes[l:])
		fmt.Println(string(PlaintextBytes))
	}
	return
}

func TestBreakCTRStatistically(t *testing.T) {
	filename := "../../challenges/challenge20.txt"
	lines, err := utils.ScanFile(filename)
	if err != nil {
		t.Errorf("ScanFile threw an error: %s", err)
		return
	}
	actual := []byte{}
	nonce := int64(0)
	Key := utils.GenerateKey()
	rawCiphertexts := [][]byte{}
	minLen := 100000
	for _, PlaintextLine := range lines {
		decoded, err := utils.ParseBase64(PlaintextLine)
		if err != nil {
			t.Errorf("ParseBase64(%q) threw an error: %s", filename, err)
			return
		}
		actual = append(actual, decoded...)
		d := pals.CTC{PlainText: pals.PlainText{
			Plaintext:      decoded,
			CryptoMaterial: pals.CryptoMaterial{Key: Key, Nonce: nonce},
		}}
		c, err := d.Encrypt()
		if err != nil {
			t.Errorf("Encrypt(%q) threw an error: %s", filename, err)
			return
		}
		if len(c.Ciphertext) < minLen {
			minLen = len(c.Ciphertext)
		}
		rawCiphertexts = append(rawCiphertexts, c.Ciphertext)
	}
	Ciphertexts := []byte{}
	for _, Ciphertext := range rawCiphertexts {
		Ciphertexts = append(Ciphertexts, Ciphertext[:minLen]...)
	}
	got, err := pals.DecryptRepeatingKeyXorWithKeysize(Ciphertexts, minLen)
	if err != nil {
		t.Errorf("DecryptRepeatingKeyXorWithKeysize threw an error: %s", err)
		return
	}
	for i, line := range lines {
		actualBytes, err := utils.ParseBase64(line)
		if err != nil {
			t.Errorf("ParseBase64(%q) threw an error: %s", filename, err)
			return
		}

		// Make a Regex to say we only want letters and numbers
		reg, err := regexp.Compile("[^a-zA-Z0-9]+")
		if err != nil {
			t.Errorf("%v", err)
		}

		decryptedString := strings.ToLower(reg.ReplaceAllString(string(got.Plaintext[minLen*i:minLen*(i+1)]), ""))
		actualTrimmedString := strings.ToLower(reg.ReplaceAllString(string(actualBytes[:minLen]), ""))

		if decryptedString != actualTrimmedString {
			t.Errorf("DecryptRepeatingKeyXorWithKeysize didn't work for block %v: \n%s\n%s", i, decryptedString, actualTrimmedString)
			return
		}
	}
}

func TestImplementMersenneTwisterRNG(t *testing.T) {
	m := mersenne.New()
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
	m := mersenne.New()
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
	m := mersenne.New()
	clone := mersenne.New()
	m.Seed(int(time.Now().UnixNano()))
	const n = 624
	for i := 0; i < n; i++ {
		clone.State[i] = mersenne.Untemper(m.Uint32())
	}
	// now the States are the same, but the clone.Index is `notSeeded` and m.Index is `n`.
	clone.Index = n
	for i := 0; i < 2*n; i++ {
		if clone.Uint32() != m.Uint32() {
			t.Errorf("Clone incorrect somehow")
			return
		}
	}
}
func TestMT19937Encryption(t *testing.T) {
	Key := utils.GenerateKey()
	original := []byte("YELLOWSUBMARINE")
	d := pals.AES_MT{PlainText: pals.PlainText{
		Plaintext:      original,
		CryptoMaterial: pals.CryptoMaterial{Key: Key},
	}}
	c, err := d.Encrypt()
	if err != nil {
		t.Errorf("Encrypt threw an error: %s", err)
		return
	}
	p, err := pals.AES_MT{EncryptedText: c}.Decrypt()
	if err != nil {
		t.Errorf("Decrypt threw an error: %s", err)
		return
	}

	if string(p.Plaintext) != string(original) {
		t.Errorf("Decrypt didn't work. Got\n`%s` instead of \n`%s`\n", p.Plaintext, original)
		return
	}
}

func TestBreakMT19937Encryption(t *testing.T) {
	const MersenneSeedSpace = 65536
	base := bytes.Repeat(utils.ByteA, 14)
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

	randomByteCount := len(c.Ciphertext) - len(base)
	merseeneValueSlice := utils.FlexibleXor(c.Ciphertext[randomByteCount:len(c.Ciphertext)], base)
	var success bool

	// try all the possible Keys until we find one that generates the known sequence in merseeneValueSlice
	for i := 0; i < MersenneSeedSpace; i++ {
		m := mersenne.New()
		m.Seed(i)

		size := len(c.Ciphertext) / pals.MersenneStreamBlockSize
		if len(c.Ciphertext)%pals.MersenneStreamBlockSize > 0 {
			size++
		}

		comparison := make([]byte, size*pals.MersenneStreamBlockSize)
		numbersNeeded := size * pals.MersenneStreamBlockSize / mersenneNumberBytes

		for i := 0; i < numbersNeeded; i++ {
			binary.LittleEndian.PutUint32(comparison[(i*mersenneNumberBytes):], m.Uint32())
		}
		if string(merseeneValueSlice) == string(comparison[randomByteCount:len(c.Ciphertext)]) {
			success = true
			break
		}
	}
	if !success {
		t.Errorf("Key not found. Should have been: %s\n", c.CryptoMaterial.Key)
	}
}

func tokenOracle() (pals.EncryptedText, error) {
	Plaintext := bytes.Repeat(utils.ByteA, mathRand.Intn(20)+4)
	return mersenneEncrypt(Plaintext, uint16(time.Now().Unix()))
}

func isTokenForRecentTime(token string) (bool, error) {
	now := int(time.Now().Unix())
	sampleText := bytes.Repeat(utils.ByteA, len(token)) // we know the oracle is just encrypting byteA repeated
	window := 10 * 60                                   // check the last 10 minutes
	for i := now; i > now-window; i-- {
		c, err := mersenneEncrypt(sampleText, uint16(i))
		if err != nil {
			return false, err
		}
		if string(c.Ciphertext) == token {
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
	found, err := isTokenForRecentTime(string(token.Ciphertext))
	if err != nil {
		t.Errorf("isTokenForRecentTime threw an error: %s", err)
		return
	}

	if !found {
		t.Errorf("Password Reset Token not identified.")
	}
}
