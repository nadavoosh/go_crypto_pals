package pals

import (
	"crypto/aes"
	"encoding/binary"

	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
	// "fmt"
)

type CTC struct {
	PlainText     PlainText
	EncryptedText EncryptedText
}

func int64ToByteArray(i int64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(i))
	return b
}

func getKeystream(Key []byte, nonce, count int64) ([]byte, error) {
	c, err := aes.NewCipher(Key)
	if err != nil {
		return nil, err
	}
	counter := append(int64ToByteArray(nonce), int64ToByteArray(count)...)
	return encryptSingleBlock(c, counter), nil
}

func (c CTC) Encrypt() (EncryptedText, error) {
	e := EncryptedText{CryptoMaterial: CryptoMaterial{Key: c.PlainText.Key}}
	blocks := chunk(c.PlainText.Plaintext, aes.BlockSize)
	for i, block := range blocks {
		Keystream, err := getKeystream(c.PlainText.Key, c.PlainText.Nonce, int64(i))
		if err != nil {
			return e, err
		}
		trimmedKeystream := Keystream[:len(block)]
		cipher := utils.FlexibleXor(block, trimmedKeystream)
		e.Ciphertext = append(e.Ciphertext, cipher...)
	}
	return e, nil
}

func (c CTC) Decrypt() (PlainText, error) {
	d := PlainText{CryptoMaterial: CryptoMaterial{Key: c.EncryptedText.Key}}
	blocks := chunk(c.EncryptedText.Ciphertext, aes.BlockSize)
	for i, block := range blocks {
		Keystream, err := getKeystream(d.Key, c.EncryptedText.Nonce, int64(i))
		if err != nil {
			return d, err
		}
		trimmedKeystream := Keystream[:len(block)]
		plain := utils.FlexibleXor(block, trimmedKeystream)
		d.Plaintext = append(d.Plaintext, plain...)
	}
	return d, nil
}
