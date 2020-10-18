package set2

import (
	"github.com/nadavoosh/go_crypto_pals/pkg/pals"
)

func appendAndEncrypt(a []byte) pals.EncryptionFn {
	return func(plain []byte) (pals.EncryptedText, error) {
		d := pals.PlainText{Plaintext: append(plain, a...), CryptoMaterial: pals.CryptoMaterial{Key: pals.FixedKey}}
		return pals.Encrypt(pals.ECB, d)
	}
}

func prependAndAppendAndEncrypt(a []byte) pals.EncryptionFn {
	return func(plain []byte) (pals.EncryptedText, error) {
		d := pals.PlainText{Plaintext: append(append(pals.FixedBytes, plain...), a...), CryptoMaterial: pals.CryptoMaterial{Key: pals.FixedKey}}
		return pals.Encrypt(pals.ECB, d)
	}
}

var YELLOWSUBMARINE = "YELLOW SUBMARINE"
