package sets

import (
	"fmt"
	"github.com/nadavoosh/go_crypto_pals/pkg/pals"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

func breakRandomAccessReadWriteAESCTR(c pals.Ciphertext, key pals.Key) (pals.Plaintext, error) {
	var p pals.Plaintext
	for offset := 0; offset < len(c); offset++ {
		for i := 0; i < 256; i++ {
			ciphertextCopy := make([]byte, len(c))
			_ = copy(ciphertextCopy, c)
			newCiphertext, err := pals.EditCTR(ciphertextCopy, key, []byte{byte(i)}, offset)
			if err != nil {
				return nil, err
			}
			if c[offset] == newCiphertext[offset] {
				p = append(p, byte(i))
				break
			}
		}
	}
	return p, nil
}

func encryptUserDataCTR(input []byte) (pals.Ciphertext, error) {
	p, err := getUserData(input)
	if err != nil {
		return nil, err
	}
	d := pals.CTR{Plaintext: p}
	c, err := d.Encrypt(utils.FixedKey)
	return c, err
}

func detectAdminStringCTR(e pals.Ciphertext) (bool, error) {
	a := pals.CTR{Ciphertext: e}
	plain, err := a.Decrypt(utils.FixedKey)
	if err != nil {
		return false, err
	}
	return detectAdminString(plain), nil
}

func encryptCBCWithKeyIV(input []byte) (pals.Ciphertext, error) {
	d := pals.AES_CBC{Plaintext: input}
	c, err := d.EncryptWithKeyIV(utils.FixedKey)
	return c, err
}

func decryptCBCWithKeyIV(e pals.Ciphertext) (pals.Plaintext, error) {
	d := pals.AES_CBC{Ciphertext: e}
	c, err := d.DecryptWithKeyIV(utils.FixedKey)
	if !utils.IsAllAscii(c) {
		return nil, fmt.Errorf("Error, invalid values found in user input: %s", c)
	}
	return c, err
}
