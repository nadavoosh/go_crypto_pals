package pals

import (
	"bytes"
	"crypto/aes"
	"fmt"

	"github.com/nadavoosh/go_crypto_pals/pkg/padding"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

func GetValidationFnForOracle(k Key) ValidationFn {
	return func(Ciphertext, IV []byte) (bool, error) {
		_, err := AES_CBC{Ciphertext: Ciphertext, IV: IV}.Decrypt(k)
		if err != nil {
			if err.Error() == "Invalid Padding" {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
}

func (c CBCPaddingOracle) DecryptCBCPadding() ([]byte, error) {
	prevCipher := c.IV
	chunks := ChunkForAES(c.Ciphertext)
	var finalPlaintext []byte
	for k := range chunks {
		var Plaintext []byte
		for j := 1; j <= aes.BlockSize; j++ {
			b, err := c.calculateNextByte(chunks[k], Plaintext, j)
			if err != nil {
				return nil, err
			}
			Plaintext = append([]byte{b}, Plaintext...)
		}
		next, err := utils.FixedXor(prevCipher, Plaintext)
		if err != nil {
			return nil, err
		}
		finalPlaintext = append(finalPlaintext, next...)
		prevCipher = chunks[k]
	}
	return padding.RemovePKCSPadding(finalPlaintext), nil
}
func (c CBCPaddingOracle) calculateNextByte(block, Plaintext []byte, j int) (byte, error) {
	base := bytes.Repeat([]byte{0}, aes.BlockSize-j)
	soFar := utils.FlexibleXor(Plaintext, bytes.Repeat([]byte{byte(j)}, len(Plaintext)))
	for i := 0; i < 256; i++ {
		filler := append(append(base, byte(i)), soFar...)
		paddingCorrect, err := c.ValidationFn(append(filler, block...), c.IV)
		if err != nil {
			return byte(0), err
		}
		if paddingCorrect {
			require := append(base, bytes.Repeat([]byte{byte(j)}, j)...)
			g, err := utils.FixedXor(filler, require)
			if err != nil {
				return byte(0), err
			}
			// fmt.Printf("YES correct padding found for byte %02v: %v : %v : %v \n", j, block, require, filler)
			return g[aes.BlockSize-j], nil
		}
	}
	return byte(0), fmt.Errorf("no correct padding found for byte %v: %v", j, block)
}
