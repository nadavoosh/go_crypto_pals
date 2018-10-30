package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
	"strings"
)

func Decrypt_AES_ECB_FromBase64File(filename, encryptionKey string) (DecryptionResult, error) {
	lines, err := ScanFile(filename)
	if err != nil {
		return DecryptionResult{}, err
	}
	return Decrypt_AES_ECB(strings.Join(lines, ""), encryptionKey)
}

func Decrypt_AES_ECB(ciphertext, encryptionKey string) (DecryptionResult, error) {
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return DecryptionResult{}, err
	}
	cipher, err := aes.NewCipher([]byte(encryptionKey))
	if err != nil {
		return DecryptionResult{}, err
	}
	var plaintext []byte
	blocks := chunk([]byte(decoded), aes.BlockSize)
	for _, block := range blocks {
		dst := make([]byte, aes.BlockSize)
		cipher.Decrypt(dst, block)
		plaintext = append(plaintext, dst...)
	}
	return DecryptionResult{plaintext: string(plaintext)}, nil
}

func smellsOfECB(b []byte) bool {
	blocks := chunk(b, aes.BlockSize)
	for _, block := range blocks {
		count := 0
		for _, b := range blocks {
			if testEq(b, block) {
				count++
			}
		}
		if count > 1 {
			return true
		}
	}
	return false
}

func DetectAESinECBFromFile(filename string) ([]HexEncoded, error) {
	lines, err := ScanFile(filename)
	var ECBs []HexEncoded
	if err != nil {
		return nil, err
	}

	for _, l := range lines {
		h := HexEncoded{hexString: l}
		if smellsOfECB(h.getBytes()) {
			// fmt.Printf("%s seemss like it was encrypted with ECB\n", h)
			ECBs = append(ECBs, h)
		}
	}
	return ECBs, nil
}
