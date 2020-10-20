package sets

import (
	"github.com/nadavoosh/go_crypto_pals/pkg/pals"
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
