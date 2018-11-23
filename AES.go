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

const (
	ECB AESMode = 0
	CBC AESMode = 1
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
	e := EncryptedText{key: d.key, iv: d.iv}
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

func GuessAESMode(e EncryptedText) AESMode {
	if smellsOfECB(e.ciphertext) {
		// fmt.Printf("Guessing ECB\n")
		return ECB
	}
	// fmt.Printf("Guessing CBC\n")
	return CBC
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
