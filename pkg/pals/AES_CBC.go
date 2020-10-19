package pals

import (
	"crypto/aes"
	"fmt"

	"github.com/nadavoosh/go_crypto_pals/pkg/padding"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

type AES_CBC struct {
	Plain     Plain
	Encrypted Encrypted
}

func (cbc AES_CBC) Encrypt(k Key) (Encrypted, error) {
	if cbc.Plain.IV == nil {
		IV, err := utils.GenerateRandomBlock()
		if err != nil {
			return Encrypted{}, err
		}
		cbc.Plain.IV = IV
	}
	e := Encrypted{IV: cbc.Plain.IV}
	padded := padding.PKCSPadding(cbc.Plain.Plaintext, aes.BlockSize)
	blocks := chunk(padded, aes.BlockSize)
	cipher := cbc.Plain.IV
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

func (cbc AES_CBC) Decrypt(k Key) (Plain, error) {
	d := Plain{}
	blocks := chunk(cbc.Encrypted.Ciphertext, aes.BlockSize)
	priorCiphertext := cbc.Encrypted.IV
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
