package pals

import (
	"crypto/aes"
	"fmt"

	"github.com/nadavoosh/go_crypto_pals/pkg/padding"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

type AES_CBC struct {
	Plaintext
	Ciphertext
	IV IV
}

func (cbc *AES_CBC) Encrypt(k Key) (Ciphertext, error) {
	if cbc.IV == nil {
		iv, err := utils.GenerateRandomBlock()
		if err != nil {
			return nil, err
		}
		cbc.IV = iv
	}
	e := Ciphertext{}
	padded := padding.PKCSPadding(cbc.Plaintext, aes.BlockSize)
	blocks := chunk(padded, aes.BlockSize)
	cipher := cbc.IV
	c, err := aes.NewCipher(k)
	if err != nil {
		return e, err
	}
	for _, block := range blocks {
		cipher = encryptSingleBlock(c, utils.FlexibleXor(block, cipher))
		e = append(e, cipher...)
	}
	return e, nil
}

func (cbc *AES_CBC) Decrypt(k Key) (Plaintext, error) {
	d := Plaintext{}
	blocks := chunk(cbc.Ciphertext, aes.BlockSize)
	priorCiphertext := cbc.IV
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
		d = append(d, plain...)
		priorCiphertext = block
	}
	if !padding.ValidatePKCS(d) {
		return d, fmt.Errorf("Invalid Padding")
	}
	d = padding.RemovePKCSPadding(d)
	return d, nil
}


func (cbc *AES_CBC) EncryptWithKeyIV(k Key) (Ciphertext, error) {
	cbc.IV = []byte(k)
	return cbc.Encrypt(k)
}

func (cbc *AES_CBC) DecryptWithKeyIV(k Key) (Plaintext, error) {
	cbc.IV = []byte(k)
	return cbc.Decrypt(k)
}
