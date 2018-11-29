package cryptopals

import (
	"crypto/aes"
	"fmt"
)

func encryptCBC(d PlainText) (EncryptedText, error) {
	e := EncryptedText{key: d.key, iv: d.iv}
	padded := PKCSPadding(d.plaintext, aes.BlockSize)
	blocks := chunk(padded, aes.BlockSize)
	cipher := d.iv
	c, err := aes.NewCipher(d.key)
	if err != nil {
		return e, err
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
		return d, err
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
	if !ValidatePKCS(d.plaintext) {
		return d, fmt.Errorf("Invalid Padding")
	}
	d.plaintext = RemovePKCSPadding(d.plaintext)
	return d, nil
}
