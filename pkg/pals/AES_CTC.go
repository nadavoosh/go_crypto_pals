package pals

import (
	"crypto/aes"
	"encoding/binary"
	// "fmt"
)

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

func encryptCTC(d PlainText) (EncryptedText, error) {
	e := EncryptedText{CryptoMaterial: CryptoMaterial{Key: d.Key}}
	blocks := chunk(d.Plaintext, aes.BlockSize)
	for i, block := range blocks {
		Keystream, err := getKeystream(d.Key, d.Nonce, int64(i))
		if err != nil {
			return e, err
		}
		trimmedKeystream := Keystream[:len(block)]
		cipher := FlexibleXor(block, trimmedKeystream)
		e.Ciphertext = append(e.Ciphertext, cipher...)
	}
	return e, nil
}

func decryptCTC(e EncryptedText) (PlainText, error) {
	d := PlainText{CryptoMaterial: CryptoMaterial{Key: e.Key}}
	blocks := chunk(e.Ciphertext, aes.BlockSize)
	for i, block := range blocks {
		Keystream, err := getKeystream(d.Key, e.Nonce, int64(i))
		if err != nil {
			return d, err
		}
		trimmedKeystream := Keystream[:len(block)]
		plain := FlexibleXor(block, trimmedKeystream)
		d.Plaintext = append(d.Plaintext, plain...)
	}
	return d, nil
}
