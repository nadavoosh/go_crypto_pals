package cryptopals

import (
	"crypto/aes"
	"fmt"
)

func getKeystream(key, nonce []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return encryptSingleBlock(c, nonce), nil
}

func encryptCTC(d PlainText) (EncryptedText, error) {
	e := EncryptedText{key: d.key}
	blocks := chunk(d.plaintext, aes.BlockSize)
	for i, block := range blocks {
		nonce := []byte(fmt.Sprintf("\x00\x00\x00\x00\x00\x00\x00\x00%c\x00\x00\x00\x00\x00\x00\x00", i))
		keystream, err := getKeystream(d.key, nonce)
		if err != nil {
			return e, err
		}
		trimmedKeystream := keystream[:len(block)]
		cipher := FlexibleXor(block, trimmedKeystream)
		e.ciphertext = append(e.ciphertext, cipher...)
	}
	return e, nil
}

func decryptCTC(e EncryptedText) (PlainText, error) {
	d := PlainText{key: e.key}
	blocks := chunk(e.ciphertext, aes.BlockSize)
	for i, block := range blocks {
		nonce := []byte(fmt.Sprintf("\x00\x00\x00\x00\x00\x00\x00\x00%c\x00\x00\x00\x00\x00\x00\x00", i))
		// fmt.Printf("nonce is %d\n", nonce)
		// fmt.Printf("key is %s\n", d.key)
		keystream, err := getKeystream(d.key, nonce)
		if err != nil {
			return d, err
		}
		trimmedKeystream := keystream[:len(block)]
		// fmt.Printf("trimmedKeystream is %d\n", trimmedKeystream)
		// fmt.Printf("block is %d\n", block)
		plain := FlexibleXor(block, trimmedKeystream)
		d.plaintext = append(d.plaintext, plain...)
	}
	return d, nil
}
