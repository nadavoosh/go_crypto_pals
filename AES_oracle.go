package cryptopals

import (
	"fmt"
)

type EncryptionFn func(plain []byte) (EncryptedText, error)
type EncryptionOracle struct {
	encrypt EncryptionFn
	mode    AESMode
}

// Decrypt decrypts fixed text that is appended to the plaintext input to fixed-key EncryptionFn
func (o EncryptionOracle) Decrypt() ([]byte, error) {
	switch o.mode {
	case ECB:
		return o.decryptECB()
		// case CBC:
		// return o.decryptCCB()
	}
	return nil, fmt.Errorf("Mode %d unknown", o.mode)

}
