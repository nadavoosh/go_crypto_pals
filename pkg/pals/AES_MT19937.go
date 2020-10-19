package pals

import (
	"encoding/binary"

	"github.com/nadavoosh/go_crypto_pals/pkg/mersenne"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

const MersenneStreamBlockSize = 8

type AES_MT struct {
	PlainText     PlainText
	EncryptedText EncryptedText
}

func seedFromKeyD(d *PlainText) {
	d.MT = mersenne.New()
	d.MT.Seed(int(binary.BigEndian.Uint16(d.Key)))
}

func seedFromKeyE(e *EncryptedText) {
	e.MT = mersenne.New()
	e.MT.Seed(int(binary.BigEndian.Uint16(e.Key)))
}

func (m AES_MT) Encrypt() (EncryptedText, error) {
	seedFromKeyD(&m.PlainText)
	return EncryptedText{CryptoMaterial: CryptoMaterial{Key: m.PlainText.Key}, Ciphertext: doMT(m.PlainText.Plaintext, m.PlainText.MT)}, nil
}

func (m AES_MT) Decrypt() (PlainText, error) {
	seedFromKeyE(&m.EncryptedText)
	return PlainText{CryptoMaterial: CryptoMaterial{Key: m.EncryptedText.Key}, Plaintext: doMT(m.EncryptedText.Ciphertext, m.EncryptedText.MT)}, nil
}

func getMTKeystream(m *mersenne.MT19937) []byte {
	Keystream := make([]byte, MersenneStreamBlockSize)
	mersenneNumberBytes := 4 // each mersenne number is 32 bits long, which is 4 bytes of Keystream
	for i := 0; i < MersenneStreamBlockSize/mersenneNumberBytes; i++ {
		binary.LittleEndian.PutUint32(Keystream[(i*mersenneNumberBytes):], m.Uint32())
	}
	return Keystream
}

func doMT(orig []byte, m *mersenne.MT19937) []byte {
	if m == nil {
		panic("oops")
	}
	var result []byte

	blocks := chunk(orig, MersenneStreamBlockSize)
	for _, block := range blocks {
		Keystream := getMTKeystream(m)
		plain := utils.FlexibleXor(block, Keystream[:len(block)])
		result = append(result, plain...)
	}
	return result
}
