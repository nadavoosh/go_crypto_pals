package cryptopals

import (
	"bytes"
	"crypto/aes"
	"fmt"
)

func decryptAndValidatePadding(e EncryptedText) (bool, error) {
	_, err := Decrypt(CBC, e)
	if err != nil {
		if err.Error() == "Invalid Padding" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (o EncryptionOracle) decryptCBCPadding() ([]byte, error) {
	c, err := o.encrypt(nil)
	if err != nil {
		return nil, err
	}
	prevCipher := c.iv
	chunks := ChunkForAES(c.ciphertext)
	var finalPlaintext []byte
	for k := range chunks {
		var plaintext []byte
		for j := 1; j <= aes.BlockSize; j++ {
			b, err := findNextByte(c, chunks[k], plaintext, j)
			if err != nil {
				return nil, err
			}
			plaintext = append([]byte{b}, plaintext...)
		}
		next, err := FixedXor(prevCipher, plaintext)
		if err != nil {
			return nil, err
		}
		finalPlaintext = append(finalPlaintext, next...)
		prevCipher = chunks[k]
	}
	return RemovePKCSPadding(finalPlaintext), nil
}
func findNextByte(c EncryptedText, block, plaintext []byte, j int) (byte, error) {
	base := bytes.Repeat([]byte{0}, aes.BlockSize-j)
	soFar := FlexibleXor(plaintext, bytes.Repeat([]byte{byte(j)}, len(plaintext)))
	for i := byte(0); i < 255; i++ {
		filler := append(append(base, byte(i)), soFar...)
		paddingCorrect, err := decryptAndValidatePadding(EncryptedText{
			ciphertext: append(filler, block...),
			key:        c.key,
			iv:         c.iv,
		})
		if err != nil {
			return byte(0), err
		}
		if paddingCorrect {
			require := append(base, bytes.Repeat([]byte{byte(j)}, j)...)
			g, err := FixedXor(filler, require)
			if err != nil {
				return byte(0), err
			}
			return g[aes.BlockSize-j], nil
		}
	}
	return byte(0), fmt.Errorf("not found")
}
