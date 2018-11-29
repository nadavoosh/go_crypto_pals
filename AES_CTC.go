package cryptopals

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

func getKeystream(key []byte, nonce, count int64) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	counter := append(int64ToByteArray(nonce), int64ToByteArray(count)...)
	return encryptSingleBlock(c, counter), nil
}

func encryptCTC(d PlainText) (EncryptedText, error) {
	e := EncryptedText{key: d.key}
	blocks := chunk(d.plaintext, aes.BlockSize)
	for i, block := range blocks {
		keystream, err := getKeystream(d.key, d.nonce, int64(i))
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
		// fmt.Printf("nonce is %d\n", nonce)
		// fmt.Printf("key is %s\n", d.key)
		keystream, err := getKeystream(d.key, e.nonce, int64(i))
		if err != nil {
			return d, err
		}
		trimmedKeystream := keystream[:len(block)]
		plain := FlexibleXor(block, trimmedKeystream)
		d.plaintext = append(d.plaintext, plain...)
	}
	return d, nil
}
