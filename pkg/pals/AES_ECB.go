package pals

import (
	"crypto/aes"

	"github.com/nadavoosh/go_crypto_pals/pkg/padding"
)

type AES_ECB struct {
	Plaintext
	Ciphertext
	padding.Padding
}

func NewAESECB(p Plaintext) AES_ECB {
	return AES_ECB{Plaintext: p, Padding: padding.PKCS}
}

func (c AES_ECB) Decrypt(k Key) (Plaintext, error) {
	cipher, err := aes.NewCipher(k)
	if err != nil {
		return Plaintext{}, err
	}
	var Plaintext []byte
	blocks := chunk(c.Ciphertext, aes.BlockSize)
	for _, block := range blocks {
		Plaintext = append(Plaintext, decryptSingleBlock(cipher, block)...)
	}
	if c.Padding == padding.PKCS {
		Plaintext = padding.RemovePKCSPadding(Plaintext)
	}
	return Plaintext, nil
}

func (c AES_ECB) Encrypt(k Key) (Ciphertext, error) {
	cipher, err := aes.NewCipher(k)
	if err != nil {
		return Ciphertext{}, err
	}
	var Ciphertext []byte
	padded := padding.PKCSPadding(c.Plaintext, aes.BlockSize)
	blocks := chunk(padded, aes.BlockSize)
	for _, block := range blocks {
		Ciphertext = append(Ciphertext, encryptSingleBlock(cipher, block)...)
	}
	return Ciphertext, nil
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
