package pals

import (
	"encoding/binary"

	"github.com/nadavoosh/go_crypto_pals/pkg/mersenne"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

const MersenneStreamBlockSize = 8

type AES_MT struct {
	Plain     Plain
	Encrypted Encrypted
	MT            *mersenne.MT19937
}

func (m *AES_MT) seedFromKey(key []byte) {
	m.MT = mersenne.New()
	m.MT.Seed(int(binary.BigEndian.Uint16(key)))
}

func (m *AES_MT) Encrypt(k Key) (Encrypted, error) {
	m.seedFromKey(k)
	return Encrypted{Ciphertext: doMT(m.Plain.Plaintext, m.MT)}, nil
}

func (m AES_MT) Decrypt(k Key) (Plain, error) {
	m.seedFromKey(k)
	return Plain{Plaintext: doMT(m.Encrypted.Ciphertext, m.MT)}, nil
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
