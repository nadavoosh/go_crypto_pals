package pals

import (
	"crypto/aes"

	"github.com/nadavoosh/go_crypto_pals/pkg/padding"
)

func DecryptECB(e EncryptedText) (PlainText, error) {
	cipher, err := aes.NewCipher(e.Key)
	if err != nil {
		return PlainText{}, err
	}
	var Plaintext []byte
	blocks := chunk(e.Ciphertext, aes.BlockSize)
	for _, block := range blocks {
		Plaintext = append(Plaintext, decryptSingleBlock(cipher, block)...)
	}
	if e.Padding == padding.PKCS {
		Plaintext = padding.RemovePKCSPadding(Plaintext)
	}
	return PlainText{Plaintext: Plaintext}, nil
}

func encryptECB(d PlainText) (EncryptedText, error) {
	cipher, err := aes.NewCipher(d.Key)
	if err != nil {
		return EncryptedText{}, err
	}
	var Ciphertext []byte
	padded := padding.PKCSPadding(d.Plaintext, aes.BlockSize)
	blocks := chunk(padded, aes.BlockSize)
	for _, block := range blocks {
		Ciphertext = append(Ciphertext, encryptSingleBlock(cipher, block)...)
	}
	return EncryptedText{Ciphertext: Ciphertext, Padding: padding.PKCS, CryptoMaterial: CryptoMaterial{Key: d.Key}}, nil
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
