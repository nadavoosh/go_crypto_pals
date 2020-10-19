package set3

import (
	"encoding/binary"

	"github.com/nadavoosh/go_crypto_pals/pkg/pals"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

const mersenneNumberBytes = 4 // each mersenne number is 32 bits long, which is 4 bytes of Keystream

func padAndEncryptFromSet() (pals.EncryptedText, error) {
	strings := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	// Plaintext, err := ParseBase64(strings[rand.Intn(len(strings)-1)])
	Plaintext, err := utils.ParseBase64(strings[0])
	if err != nil {
		return pals.EncryptedText{}, err
	}
	d := pals.PlainText{Plaintext: []byte(Plaintext), CryptoMaterial: pals.CryptoMaterial{Key: utils.FixedKey, IV: utils.GenerateKey()}}
	return pals.AES_CBC{PlainText: d}.Encrypt()
}

func mersenneEncrypt(Plaintext []byte, seed uint16) (pals.EncryptedText, error) {
	KeyByteArray := make([]byte, 2)
	binary.BigEndian.PutUint16(KeyByteArray, seed)

	d := pals.AES_MT{PlainText: pals.PlainText{
		Plaintext:      Plaintext,
		CryptoMaterial: pals.CryptoMaterial{Key: KeyByteArray},
	}}
	return d.Encrypt()
}
