package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	// "log"
	mathRand "math/rand"
)

func DecryptAESECBMode(e EncryptedText) (PlainText, error) {
	cipher, err := aes.NewCipher(e.key)
	if err != nil {
		return PlainText{}, err
	}
	var plaintext []byte
	blocks := chunk(e.ciphertext, aes.BlockSize)
	for _, block := range blocks {
		plaintext = append(plaintext, decryptSingleBlock(cipher, block)...)
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

func EncryptAESECBMode(d PlainText) (EncryptedText, error) {
	cipher, err := aes.NewCipher(d.key)
	if err != nil {
		return EncryptedText{}, err
	}
	var ciphertext []byte
	blocks := chunk(d.plaintext, aes.BlockSize)
	for _, block := range blocks {
		ciphertext = append(ciphertext, encryptSingleBlock(cipher, block)...)
	}
	return EncryptedText{ciphertext: ciphertext}, nil
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

func DetectAESECBMode(lines []string) ([]HexEncoded, error) {
	var ECBs []HexEncoded
	for _, l := range lines {
		h := HexEncoded{hexString: l}
		if smellsOfECB(h.getBytes()) {
			ECBs = append(ECBs, h)
		}
	}
	return ECBs, nil
}

func EncryptCBCMode(d PlainText, iv []byte) (EncryptedText, error) {
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

func DecryptCBCMode(e EncryptedText, iv []byte) (PlainText, error) {
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

func EncryptionOracle(p []byte) (EncryptedText, error) {
	b, err := addRandomBytes(p)
	if err != nil {
		return EncryptedText{}, err
	}
	key, err := generateRandomBlock()
	if err != nil {
		return EncryptedText{}, err
	}
	d := PlainText{plaintext: PKCSPadding(b, aes.BlockSize), key: key}
	shouldUseECB := mathRand.Float64() < float64(0.5)
	if shouldUseECB {
		fmt.Printf("Encrypting with ECB Mode\n")
		return EncryptAESECBMode(d)
	}
	fmt.Printf("Encrypting with CBC Mode\n")
	iv, err := generateRandomBlock()
	if err != nil {
		return EncryptedText{}, err
	}

	return EncryptCBCMode(d, iv)

}

func GuessAESMode(e EncryptedText) string {
	if smellsOfECB(e.ciphertext) {
		fmt.Printf("Guessing ECB\n")
		return "ECB Mode"
	}
	fmt.Printf("Guessing CBC\n")
	return "CBC Mode"
}
