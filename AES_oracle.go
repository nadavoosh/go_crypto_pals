package cryptopals

import (
	"fmt"
)

type EncryptionFn func(plain []byte) (EncryptedText, error)
type ValidationFn func(cipher, iv []byte) (bool, error)
type AESOracleMode int

const (
	ECBAppend  AESOracleMode = 0
	CBCPadding AESOracleMode = 1
)

type EncryptionOracle struct {
	encrypt EncryptionFn
	mode    AESOracleMode
}

// Decrypt decrypts fixed text that is appended to the plaintext input to fixed-key EncryptionFn
func (o EncryptionOracle) Decrypt() ([]byte, error) {
	switch o.mode {
	case ECBAppend:
		return o.decryptECBAppend()
	}
	return nil, fmt.Errorf("Mode %d unknown", o.mode)
}

type CBCPaddingOracle struct {
	iv           []byte
	ciphertext   []byte
	validationFn ValidationFn
}

// Decrypt decrypts fixed text that is appended to the plaintext input to fixed-key EncryptionFn
func (o CBCPaddingOracle) Decrypt() ([]byte, error) {
	return o.decryptCBCPadding()
}
