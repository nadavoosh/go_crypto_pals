package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	mathRand "math/rand"
)

type AESMode int
type EncryptionFn func(plain []byte) (EncryptedText, error)

const (
	ECB AESMode = 0
	CBC AESMode = 1
)

type Padding int

const (
	None Padding = 0
	PKCS Padding = 1
)

func Encrypt(mode AESMode, d PlainText) (EncryptedText, error) {
	switch mode {
	case ECB:
		return EncryptECB(d)
	case CBC:
		if d.iv == nil {
			iv, err := generateRandomBlock()
			if err != nil {
				return EncryptedText{}, err
			}
			d.iv = iv
		}
		return encryptCBC(d)
	default:
		return EncryptedText{}, fmt.Errorf("Mode %d unknown", mode)
	}
}

func Decrypt(mode AESMode, e EncryptedText) (PlainText, error) {
	switch mode {
	case ECB:
		return DecryptECB(e)
	case CBC:
		if e.iv == nil {
			iv, err := generateRandomBlock()
			if err != nil {
				return PlainText{}, err
			}
			e.iv = iv
		}
		return decryptCBC(e)
	default:
		return PlainText{}, fmt.Errorf("Mode %d unknown", mode)
	}
}

func DecryptECB(e EncryptedText) (PlainText, error) {
	cipher, err := aes.NewCipher(e.key)
	if err != nil {
		return PlainText{}, err
	}
	var plaintext []byte
	blocks := chunk(e.ciphertext, aes.BlockSize)
	for _, block := range blocks {
		plaintext = append(plaintext, decryptSingleBlock(cipher, block)...)
	}
	if e.padding == PKCS {
		plaintext = RemovePKCSPadding(plaintext)
	}
	return PlainText{plaintext: plaintext}, nil
}

func RemovePKCSPadding(b []byte) []byte {
	paddingCount := int(b[len(b)-1])
	return b[:len(b)-paddingCount]
}

func encryptSingleBlock(cipher cipher.Block, plaintext []byte) []byte {
	dst := make([]byte, aes.BlockSize)
	cipher.Encrypt(dst, plaintext)
	return dst
}

func decryptSingleBlock(cipher cipher.Block, ciphertext []byte) []byte {
	dst := make([]byte, aes.BlockSize)
	cipher.Decrypt(dst, ciphertext)
	return dst
}

func EncryptECB(d PlainText) (EncryptedText, error) {
	cipher, err := aes.NewCipher(d.key)
	if err != nil {
		return EncryptedText{}, err
	}
	var ciphertext []byte
	// fmt.Printf("running with len(%d) \n", len(d.plaintext))
	padded := PKCSPadding(d.plaintext, aes.BlockSize)
	blocks := chunk(padded, aes.BlockSize)
	for _, block := range blocks {
		ciphertext = append(ciphertext, encryptSingleBlock(cipher, block)...)
	}
	return EncryptedText{ciphertext: ciphertext, padding: PKCS, key: d.key}, nil
}

func smellsOfECB(b []byte) bool {
	blocks := chunk(b, aes.BlockSize)
	m := make(map[string]int64)
	for _, block := range blocks {
		for _, b := range blocks {
			if testEq(b, block) {
				m[string(block)]++
			}
		}
	}
	for _, v := range m {
		if v > 2 {
			return true
		}
	}
	return false
}

func DetectECBMode(lines []string) ([]HexEncoded, error) {
	var ECBs []HexEncoded
	for _, l := range lines {
		h := HexEncoded{hexString: l}
		if smellsOfECB(h.getBytes()) {
			ECBs = append(ECBs, h)
		}
	}
	return ECBs, nil
}

func encryptCBC(d PlainText) (EncryptedText, error) {
	e := EncryptedText{key: d.key}
	blocks := chunk(d.plaintext, aes.BlockSize)
	cipher := d.iv
	c, err := aes.NewCipher(d.key)
	if err != nil {
		return EncryptedText{}, err
	}
	for _, block := range blocks {
		cipher = encryptSingleBlock(c, FlexibleXor(block, cipher))
		e.ciphertext = append(e.ciphertext, cipher...)

	}
	return e, nil
}

func decryptCBC(e EncryptedText) (PlainText, error) {
	d := PlainText{key: e.key}
	blocks := chunk(e.ciphertext, aes.BlockSize)
	priorCiphertext := e.iv
	c, err := aes.NewCipher(e.key)
	if err != nil {
		return PlainText{}, err
	}
	for _, block := range blocks {
		if err != nil {
			return d, err
		}
		plain, err := FixedXor(decryptSingleBlock(c, block), priorCiphertext)
		if err != nil {
			return d, err
		}
		d.plaintext = append(d.plaintext, plain...)
		priorCiphertext = block
	}
	return d, nil
}

func generateRandomBlock() ([]byte, error) {
	key := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	return key, err
}

func addRandomBytes(p []byte) ([]byte, error) {
	lenBefore := mathRand.Intn(5) + 5
	lenAfter := len(p) + lenBefore%16
	beforeBytes := make([]byte, lenBefore)
	afterBytes := make([]byte, lenAfter)
	_, err := rand.Read(beforeBytes)
	if err != nil {
		return nil, err
	}
	_, err = rand.Read(afterBytes)
	if err != nil {
		return nil, err
	}
	return append(append(beforeBytes, p...), afterBytes...), nil
}

func EncryptionOracle(plain []byte, mode AESMode) (EncryptedText, error) {
	b, err := addRandomBytes(plain)
	if err != nil {
		return EncryptedText{}, err
	}
	key, err := generateRandomBlock()
	if err != nil {
		return EncryptedText{}, err
	}
	d := PlainText{plaintext: b, key: key}
	switch mode {
	case ECB:
		fmt.Printf("Encrypting with ECB Mode\n")
		return Encrypt(ECB, d)
	case CBC:
		fmt.Printf("Encrypting with CBC Mode\n")
		return Encrypt(CBC, d)
	default:
		return EncryptedText{}, fmt.Errorf("Mode %d unknown", mode)
	}
}

func GuessAESMode(e EncryptedText) AESMode {
	if smellsOfECB(e.ciphertext) {
		fmt.Printf("Guessing ECB\n")
		return ECB
	}
	fmt.Printf("Guessing CBC\n")
	return CBC
}

var unknownKey = GenerateKey()

func GenerateKey() []byte {
	k, _ := generateRandomBlock()
	return k
}

func GetEncryptionFunction(prepend []byte) func(plain []byte) (EncryptedText, error) {
	return func(plain []byte) (EncryptedText, error) {
		d := PlainText{plaintext: append(plain, prepend...), key: unknownKey}
		return EncryptECB(d)
	}
}

func inferBlocksize(f EncryptionFn) (int, error) {
	i := 2
	initial, err := f([]byte("A"))
	if err != nil {
		return 0, err
	}
	for true {
		next, err := f(bytes.Repeat([]byte("A"), i))
		if err != nil {
			return 0, err
		}
		diff := len(next.ciphertext) - len(initial.ciphertext)
		if diff > 0 {
			return diff, nil
		}
		i++
	}
	return 0, nil
}

var byteA = []byte("A")

func buildMap(f EncryptionFn, testInput []byte, blocksize, blockNumber int) (map[string]byte, error) {
	m := make(map[string]byte)
	for i := byte(0); i < 255; i++ {
		b := append(testInput, i)
		p, err := f(b)
		if err != nil {
			return nil, err
		}
		ret := p.ciphertext[(blockNumber * blocksize) : (blockNumber+1)*blocksize]
		m[string(ret)] = i
	}
	return m, nil
}

func DecryptOracle(f EncryptionFn) ([]byte, error) {
	blocksize, err := inferBlocksize(f)
	if err != nil {
		return nil, err
	}
	ci, err := f(bytes.Repeat(byteA, 2*blocksize))
	if err != nil {
		return nil, err
	}
	if !smellsOfECB(ci.ciphertext) {
		return nil, fmt.Errorf("ECB Mode not detected in ciphertext")
	}
	encryptedText, err := f(nil)
	if err != nil {
		return nil, err
	}
	var nPlain []byte
	for n := 0; n < len(encryptedText.ciphertext)/blocksize; n++ {
		for j := 0; j < blocksize; j++ {
			baseInput := bytes.Repeat(byteA, blocksize-(j+1))

			testInput := append(baseInput, nPlain...)

			m, err := buildMap(f, testInput, blocksize, n)
			if err != nil {
				return nil, err
			}
			p, err := f(baseInput)
			if err != nil {
				return nil, err
			}
			actual := p.ciphertext[(n * blocksize) : (n+1)*blocksize]
			if deciphered, ok := m[string(actual)]; ok {
				nPlain = append(nPlain, deciphered)
			} else {
				fmt.Printf("encrypted string %d not found in decryption map for byte %d\n", actual, j)
			}
		}
	}
	return RemovePKCSPadding(nPlain), nil
}
