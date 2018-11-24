package cryptopals

import "crypto/aes"

func decryptECB(e EncryptedText) (PlainText, error) {
	cipher, err := aes.NewCipher(e.key)
	if err != nil {
		return PlainText{}, err
	}
	var plaintext []byte
	blocks := chunk(e.ciphertext, aes.BlockSize)
	for _, block := range blocks {
		plaintext = append(plaintext, decryptSingleBlock(cipher, block)...)
	}
	if e.padding == PKCS {
		plaintext = RemovePKCSPadding(plaintext)
	}
	return PlainText{plaintext: plaintext}, nil
}

func encryptECB(d PlainText) (EncryptedText, error) {
	cipher, err := aes.NewCipher(d.key)
	if err != nil {
		return EncryptedText{}, err
	}
	var ciphertext []byte
	padded := PKCSPadding(d.plaintext, aes.BlockSize)
	blocks := chunk(padded, aes.BlockSize)
	for _, block := range blocks {
		ciphertext = append(ciphertext, encryptSingleBlock(cipher, block)...)
	}
	return EncryptedText{ciphertext: ciphertext, padding: PKCS, key: d.key}, nil
}

func smellsOfECB(b []byte) bool {
	blocks := chunk(b, aes.BlockSize)
	m := make(map[string]int64)
	for _, block := range blocks {
		for _, b := range blocks {
			if testEq(b, block) {
				m[string(block)]++
			}
		}
	}
	for _, v := range m {
		if v > 2 {
			return true
		}
	}
	return false
}
