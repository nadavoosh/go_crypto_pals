package pals

import (
	"crypto/aes"
	"fmt"

	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

func encryptCBC(d PlainText) (EncryptedText, error) {
	e := EncryptedText{CryptoMaterial: CryptoMaterial{Key: d.Key, IV: d.IV}}
	padded := PKCSPadding(d.Plaintext, aes.BlockSize)
	blocks := chunk(padded, aes.BlockSize)
	cipher := d.IV
	c, err := aes.NewCipher(d.Key)
	if err != nil {
		return e, err
	}
	for _, block := range blocks {
		cipher = encryptSingleBlock(c, utils.FlexibleXor(block, cipher))
		e.Ciphertext = append(e.Ciphertext, cipher...)
	}
	return e, nil
}

func DecryptCBC(e EncryptedText) (PlainText, error) {
	d := PlainText{CryptoMaterial: CryptoMaterial{Key: e.Key}}
	blocks := chunk(e.Ciphertext, aes.BlockSize)
	priorCiphertext := e.IV
	c, err := aes.NewCipher(e.Key)
	if err != nil {
		return d, err
	}
	for _, block := range blocks {
		if err != nil {
			return d, err
		}
		plain, err := utils.FixedXor(decryptSingleBlock(c, block), priorCiphertext)
		if err != nil {
			return d, err
		}
		d.Plaintext = append(d.Plaintext, plain...)
		priorCiphertext = block
	}
	if !ValidatePKCS(d.Plaintext) {
		return d, fmt.Errorf("Invalid Padding")
	}
	d.Plaintext = RemovePKCSPadding(d.Plaintext)
	return d, nil
}
