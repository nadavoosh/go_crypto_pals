package cryptopals

import (
	"bytes"
	"crypto/aes"
	"fmt"
)

func getValidationFnForOracle(key []byte) ValidationFn {
	return func(ciphertext, iv []byte) (bool, error) {
		e := EncryptedText{ciphertext: ciphertext, CryptoMaterial: CryptoMaterial{key: key, iv: iv}}
		_, err := Decrypt(CBC, e)
		if err != nil {
			if err.Error() == "Invalid Padding" {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
}

func (c CBCPaddingOracle) decryptCBCPadding() ([]byte, error) {
	prevCipher := c.iv
	chunks := ChunkForAES(c.ciphertext)
	var finalPlaintext []byte
	for k := range chunks {
		var plaintext []byte
		for j := 1; j <= aes.BlockSize; j++ {
			b, err := c.findNextByte(chunks[k], plaintext, j)
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
func (c CBCPaddingOracle) findNextByte(block, plaintext []byte, j int) (byte, error) {
	base := bytes.Repeat([]byte{0}, aes.BlockSize-j)
	soFar := FlexibleXor(plaintext, bytes.Repeat([]byte{byte(j)}, len(plaintext)))
	for i := byte(0); i < 255; i++ {
		filler := append(append(base, byte(i)), soFar...)
		paddingCorrect, err := c.validationFn(append(filler, block...), c.iv)
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
	return byte(0), fmt.Errorf("next byte not found")
}
