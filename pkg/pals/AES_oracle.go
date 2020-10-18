package pals

import (
	"fmt"
)

type EncryptionFn func(plain []byte) (EncryptedText, error)
type ValidationFn func(cipher, IV []byte) (bool, error)
type AESOracleMode int

const (
	ECBAppend  AESOracleMode = 0
	CBCPadding AESOracleMode = 1
)

type EncryptionOracle struct {
	Encrypt EncryptionFn
	Mode    AESOracleMode
}

// Decrypt decrypts fixed text that is appended to the Plaintext input to fixed-Key EncryptionFn
func (o EncryptionOracle) Decrypt() ([]byte, error) {
	switch o.Mode {
	case ECBAppend:
		return o.DecryptECBAppend()
	}
	return nil, fmt.Errorf("Mode %d unknown", o.Mode)
}

type CBCPaddingOracle struct {
	IV           []byte
	Ciphertext   []byte
	ValidationFn ValidationFn
}

// Decrypt decrypts fixed text that is appended to the Plaintext input to fixed-Key EncryptionFn
func (o CBCPaddingOracle) Decrypt() ([]byte, error) {
	return o.DecryptCBCPadding()
}
