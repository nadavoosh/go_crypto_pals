package pals

import (
	"crypto/aes"

	"github.com/nadavoosh/go_crypto_pals/pkg/padding"
)

type AES_ECB struct {
	PlainText     PlainText
	EncryptedText EncryptedText
}

func (c AES_ECB) Decrypt() (PlainText, error) {
	cipher, err := aes.NewCipher(c.EncryptedText.Key)
	if err != nil {
		return PlainText{}, err
	}
	var Plaintext []byte
	blocks := chunk(c.EncryptedText.Ciphertext, aes.BlockSize)
	for _, block := range blocks {
		Plaintext = append(Plaintext, decryptSingleBlock(cipher, block)...)
	}
	if c.EncryptedText.Padding == padding.PKCS {
		Plaintext = padding.RemovePKCSPadding(Plaintext)
	}
	return PlainText{Plaintext: Plaintext}, nil
}

func (c AES_ECB) Encrypt() (EncryptedText, error) {
	cipher, err := aes.NewCipher(c.PlainText.Key)
	if err != nil {
		return EncryptedText{}, err
	}
	var Ciphertext []byte
	padded := padding.PKCSPadding(c.PlainText.Plaintext, aes.BlockSize)
	blocks := chunk(padded, aes.BlockSize)
	for _, block := range blocks {
		Ciphertext = append(Ciphertext, encryptSingleBlock(cipher, block)...)
	}
	return EncryptedText{Ciphertext: Ciphertext, Padding: padding.PKCS, Key: c.PlainText.Key}, nil
}

func SmellsOfECB(b []byte) bool {
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
