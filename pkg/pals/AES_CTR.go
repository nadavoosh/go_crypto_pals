package pals

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"

	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

type CTR struct {
	Plaintext
	Ciphertext
	Nonce int64
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

func (c CTR) Encrypt(k Key) (Ciphertext, error) {
	e := Ciphertext{}
	blocks := chunk(c.Plaintext, aes.BlockSize)
	for i, block := range blocks {
		Keystream, err := getKeystream(k, c.Nonce, int64(i))
		if err != nil {
			return e, err
		}
		trimmedKeystream := Keystream[:len(block)]
		cipher := utils.FlexibleXor(block, trimmedKeystream)
		e = append(e, cipher...)
	}
	return e, nil
}

func (c CTR) Decrypt(k Key) (Plaintext, error) {
	d := Plaintext{}
	blocks := chunk(c.Ciphertext, aes.BlockSize)
	for i, block := range blocks {
		Keystream, err := getKeystream(k, c.Nonce, int64(i))
		if err != nil {
			return d, err
		}
		trimmedKeystream := Keystream[:len(block)]
		plain := utils.FlexibleXor(block, trimmedKeystream)
		d = append(d, plain...)
	}
	return d, nil
}

func EditCTR(ciphertext Ciphertext, key Key, newtext Plaintext, offset int) (Ciphertext, error) {
	var defaultNonce int64
	res := make([]byte, len(ciphertext)) //TODO handle case where len(newtext) + offset is greater than this

	seekStart := offset / aes.BlockSize
	seekStop := (offset + len(newtext)) / aes.BlockSize

	prefill := offset % aes.BlockSize

	if (prefill+len(newtext))%aes.BlockSize > 0 {
		seekStop++
	}

	paddedNewtext := append(bytes.Repeat([]byte{0}, offset), newtext...)
	newBlocks := chunk(paddedNewtext, aes.BlockSize)

	res = ciphertext[:aes.BlockSize*seekStart]
	// fmt.Printf("seekStart %v, seekStop %v\n", seekStart, seekStop)
	for i := seekStart; i < seekStop; i++ {
		// fmt.Printf("block %d\n", i)
		// fmt.Printf("blocks[i] %d\n", blocks[i])
		Keystream, err := getKeystream(key, defaultNonce, int64(i))
		if err != nil {
			return nil, err
		}
		trimmedKeystream := Keystream[:len(newBlocks[i])]
		newEncryptedBlock := utils.FlexibleXor(newBlocks[i], trimmedKeystream)
		// fmt.Printf("resultBlock %d\n", resultBlock)
		res = append(res, newEncryptedBlock...)
	}
	if len(ciphertext) > len(res) {
		res = append(res, ciphertext[len(ciphertext):]...)
	}
	return res, nil
}
