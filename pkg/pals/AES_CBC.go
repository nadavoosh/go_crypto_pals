package pals

import (
	"crypto/aes"
	"fmt"

	"github.com/nadavoosh/go_crypto_pals/pkg/padding"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

type AES_CBC struct {
	PlainText     PlainText
	EncryptedText EncryptedText
}

func (cbc AES_CBC) Encrypt(k Key) (EncryptedText, error) {
	if cbc.PlainText.IV == nil {
		IV, err := utils.GenerateRandomBlock()
		if err != nil {
			return EncryptedText{}, err
		}
		cbc.PlainText.IV = IV
	}
	e := EncryptedText{IV: cbc.PlainText.IV}
	padded := padding.PKCSPadding(cbc.PlainText.Plaintext, aes.BlockSize)
	blocks := chunk(padded, aes.BlockSize)
	cipher := cbc.PlainText.IV
	c, err := aes.NewCipher(k)
	if err != nil {
		return e, err
	}
	for _, block := range blocks {
		cipher = encryptSingleBlock(c, utils.FlexibleXor(block, cipher))
		e.Ciphertext = append(e.Ciphertext, cipher...)
	}
	return e, nil
}

func (cbc AES_CBC) Decrypt(k Key) (PlainText, error) {
	d := PlainText{}
	blocks := chunk(cbc.EncryptedText.Ciphertext, aes.BlockSize)
	priorCiphertext := cbc.EncryptedText.IV
	c, err := aes.NewCipher(k)
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
	if !padding.ValidatePKCS(d.Plaintext) {
		return d, fmt.Errorf("Invalid Padding")
	}
	d.Plaintext = padding.RemovePKCSPadding(d.Plaintext)
	return d, nil
}
