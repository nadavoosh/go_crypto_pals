package cryptopals

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"log"
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
		dst := make([]byte, aes.BlockSize)
		cipher.Decrypt(dst, block)
		plaintext = append(plaintext, dst...)
	}
	return PlainText{plaintext: plaintext}, nil
}

func EncryptAESECBMode(d PlainText) (EncryptedText, error) {
	cipher, err := aes.NewCipher(d.key)
	if err != nil {
		return EncryptedText{}, err
	}
	var ciphertext []byte
	blocks := chunk(d.plaintext, aes.BlockSize)
	for _, block := range blocks {
		dst := make([]byte, aes.BlockSize)
		cipher.Encrypt(dst, block)
		ciphertext = append(ciphertext, dst...)
	}
	return EncryptedText{ciphertext: ciphertext}, nil
}

func smellsOfECB(b []byte) bool {
	blocks := chunk(b, aes.BlockSize)
	for _, block := range blocks {
		countRepeated := 0
		for _, b := range blocks {
			if testEq(b, block) {
				countRepeated++
				continue
			}
		}
		// fmt.Printf("countRepeated is %d\n", countRepeated)
		if countRepeated > 2 {
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
	cipher := EncryptedText{ciphertext: iv}
	for _, block := range blocks {
		cipher, err := EncryptAESECBMode(PlainText{key: d.key, plaintext: FlexibleXor(block, cipher.ciphertext)})
		if err != nil {
			log.Fatal(err)
			return e, err
		}
		e.ciphertext = append(e.ciphertext, cipher.ciphertext...)

	}
	return e, nil
}

func DecryptCBCMode(e EncryptedText, iv []byte) (PlainText, error) {
	d := PlainText{key: e.key}
	blocks := chunk(e.ciphertext, aes.BlockSize)
	priorCiphertext := iv
	for _, block := range blocks {
		res, err := DecryptAESECBMode(EncryptedText{key: e.key, ciphertext: block})
		if err != nil {
			return d, err
		}
		plain, err := FixedXor(res.plaintext, priorCiphertext)
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
	if mathRand.Intn(2) == 0 {
		fmt.Printf("Encrypting with ECB Mode\n")
		return EncryptAESECBMode(d)
	}
	iv, err := generateRandomBlock()
	if err != nil {
		return EncryptedText{}, err
	}
	fmt.Printf("Encrypting with CBC Mode\n")
	return EncryptCBCMode(d, iv)

}

func GuessAESMode(e EncryptedText) string {
	if smellsOfECB(e.ciphertext) {
		return "ECB Mode"
	}
	return "CBC Mode"
}
