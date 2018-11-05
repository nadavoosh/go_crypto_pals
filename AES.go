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

func EncryptCBC(d PlainText, iv []byte) (EncryptedText, error) {
	e := EncryptedText{key: d.key}
	blocks := chunk(d.plaintext, aes.BlockSize)
	cipher := iv
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

func DecryptCBC(e EncryptedText, iv []byte) (PlainText, error) {
	d := PlainText{key: e.key}
	blocks := chunk(e.ciphertext, aes.BlockSize)
	priorCiphertext := iv
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
		return EncryptECB(d)
	case CBC:
		fmt.Printf("Encrypting with CBC Mode\n")
		iv, err := generateRandomBlock()
		if err != nil {
			return EncryptedText{}, err
		}
		return EncryptCBC(d, iv)
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

var unknownKey, _ = generateRandomBlock()

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

func ByteByByteECBDecryption(c []byte) (string, error) {
	f := GetEncryptionFunction(c)
	blocksize, err := inferBlocksize(f)
	// fmt.Printf("blocksize is %d\n", blocksize)
	if err != nil {
		return "", err
	}
	basePadding := blocksize - (len(c) % blocksize)
	paddingLen := basePadding + 2*blocksize
	ciphertext := append(c, bytes.Repeat([]byte("A"), paddingLen)...)
	if !smellsOfECB(ciphertext) {
		return "", fmt.Errorf("ECB Mode not detected in ciphertext")
	}
	var plaintext []byte
	A := []byte("A")
	cipherBlocks := chunk(c, blocksize)
	for _, block := range cipherBlocks {
		f = GetEncryptionFunction(block)
		// fmt.Printf("Decrypting block %d of ciphertext, with len %d\n", n, len(block))
		var nPlain []byte
		for j := 0; j < len(block); j++ {
			baseInput := bytes.Repeat(A, blocksize-(j+1))
			// fmt.Printf("baseInput has len %d: %s\n", len(baseInput), baseInput)
			m := make(map[string]byte)
			for i := byte(0); i < 255; i++ {
				testInput := append(baseInput, nPlain...)
				b := append(testInput, i)
				// fmt.Printf("b is %s\n", b)
				p, err := f(b)
				if err != nil {
					return "", err
				}
				ret := p.ciphertext[0:blocksize]
				m[string(ret)] = i
			}
			p, err := f(baseInput)
			if err != nil {
				return "", err
			}
			actual := p.ciphertext[0:blocksize]
			deciphered, ok := m[string(actual)]
			if ok == false {
				return "", fmt.Errorf("encrypted string %d not found in decryption map for byte %d", actual, j)
			}
			nPlain = append(nPlain, deciphered)
		}
		plaintext = append(plaintext, nPlain...)
	}
	return string(plaintext), nil
}
