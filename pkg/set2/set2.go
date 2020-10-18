package set2

import (
	"github.com/nadavoosh/go_crypto_pals/pkg/pals"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

func appendAndEncrypt(a []byte) pals.EncryptionFn {
	return func(plain []byte) (pals.EncryptedText, error) {
		d := pals.PlainText{Plaintext: append(plain, a...), CryptoMaterial: pals.CryptoMaterial{Key: utils.FixedKey}}
		return pals.Encrypt(pals.ECB, d)
	}
}

func prependAndAppendAndEncrypt(a []byte) pals.EncryptionFn {
	return func(plain []byte) (pals.EncryptedText, error) {
		d := pals.PlainText{Plaintext: append(append(utils.FixedBytes, plain...), a...), CryptoMaterial: pals.CryptoMaterial{Key: utils.FixedKey}}
		return pals.Encrypt(pals.ECB, d)
	}
}

var YELLOWSUBMARINE = "YELLOW SUBMARINE"
