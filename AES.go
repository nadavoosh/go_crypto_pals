package cryptopals

import (
	"crypto/aes"
	"log"
)

func DecryptAESECB(e EncryptionResult) (DecryptionResult, error) {
	cipher, err := aes.NewCipher(e.key)
	if err != nil {
		return DecryptionResult{}, err
	}
	var plaintext []byte
	blocks := chunk(e.ciphertext, aes.BlockSize)
	for _, block := range blocks {
		dst := make([]byte, aes.BlockSize)
		cipher.Decrypt(dst, block)
		plaintext = append(plaintext, dst...)
	}
	return DecryptionResult{plaintext: plaintext}, nil
}

func EncryptAESECB(d DecryptionResult) (EncryptionResult, error) {
	cipher, err := aes.NewCipher(d.key)
	if err != nil {
		return EncryptionResult{}, err
	}
	var ciphertext []byte
	blocks := chunk(d.plaintext, aes.BlockSize)
	for _, block := range blocks {
		dst := make([]byte, aes.BlockSize)
		cipher.Encrypt(dst, block)
		ciphertext = append(ciphertext, dst...)
	}
	return EncryptionResult{ciphertext: ciphertext}, nil
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

func DetectAESinECB(lines []string) ([]HexEncoded, error) {
	var ECBs []HexEncoded
	for _, l := range lines {
		h := HexEncoded{hexString: l}
		if smellsOfECB(h.getBytes()) {
			ECBs = append(ECBs, h)
		}
	}
	return ECBs, nil
}

func EncryptCBCMode(d DecryptionResult, iv []byte) (EncryptionResult, error) {
	e := EncryptionResult{key: d.key}
	blocks := chunk(d.plaintext, aes.BlockSize)
	cipher := EncryptionResult{ciphertext: iv}
	for _, block := range blocks {
		cipher, err := EncryptAESECB(DecryptionResult{key: d.key, plaintext: FlexibleXor(block, cipher.ciphertext)})
		if err != nil {
			log.Fatal(err)
			return e, err
		}
		e.ciphertext = append(e.ciphertext, cipher.ciphertext...)

	}
	return e, nil
}

func DecryptCBCMode(e EncryptionResult, iv []byte) (DecryptionResult, error) {
	d := DecryptionResult{key: e.key}
	blocks := chunk(e.ciphertext, aes.BlockSize)
	priorCiphertext := iv
	for _, block := range blocks {
		res, err := DecryptAESECB(EncryptionResult{key: e.key, ciphertext: block})
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
