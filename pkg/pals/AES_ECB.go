package pals

import (
	"crypto/aes"

	"github.com/nadavoosh/go_crypto_pals/pkg/padding"
)

type AES_ECB struct {
	Plain     Plain
	Encrypted Encrypted
}

func NewAESECB(p Plain) AES_ECB {
	return AES_ECB{Plain: p}
}

func (c AES_ECB) Decrypt(k Key) (Plain, error) {
	cipher, err := aes.NewCipher(k)
	if err != nil {
		return Plain{}, err
	}
	var Plaintext []byte
	blocks := chunk(c.Encrypted.Ciphertext, aes.BlockSize)
	for _, block := range blocks {
		Plaintext = append(Plaintext, decryptSingleBlock(cipher, block)...)
	}
	if c.Encrypted.Padding == padding.PKCS {
		Plaintext = padding.RemovePKCSPadding(Plaintext)
	}
	return Plain{Plaintext: Plaintext}, nil
}

func (c AES_ECB) Encrypt(k Key) (Encrypted, error) {
	cipher, err := aes.NewCipher(k)
	if err != nil {
		return Encrypted{}, err
	}
	var Ciphertext []byte
	padded := padding.PKCSPadding(c.Plain.Plaintext, aes.BlockSize)
	blocks := chunk(padded, aes.BlockSize)
	for _, block := range blocks {
		Ciphertext = append(Ciphertext, encryptSingleBlock(cipher, block)...)
	}
	return Encrypted{Ciphertext: Ciphertext, Padding: padding.PKCS}, nil
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
