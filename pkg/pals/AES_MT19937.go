package pals

import (
	"encoding/binary"
)

const MersenneStreamBlockSize = 8

func seedFromKeyD(d *PlainText) {
	d.MT = NewMersenneTwister()
	d.MT.Seed(int(binary.BigEndian.Uint16(d.Key)))
}

func seedFromKeyE(e *EncryptedText) {
	e.MT = NewMersenneTwister()
	e.MT.Seed(int(binary.BigEndian.Uint16(e.Key)))
}

func encryptMT(d PlainText) (EncryptedText, error) {
	seedFromKeyD(&d)
	return EncryptedText{CryptoMaterial: CryptoMaterial{Key: d.Key}, Ciphertext: doMT(d.Plaintext, d.MT)}, nil
}

func decryptMT(e EncryptedText) (PlainText, error) {
	seedFromKeyE(&e)
	return PlainText{CryptoMaterial: CryptoMaterial{Key: e.Key}, Plaintext: doMT(e.Ciphertext, e.MT)}, nil
}

func getMTKeystream(m *MT19937) []byte {
	Keystream := make([]byte, MersenneStreamBlockSize)
	mersenneNumberBytes := 4 // each mersenne number is 32 bits long, which is 4 bytes of Keystream
	for i := 0; i < MersenneStreamBlockSize/mersenneNumberBytes; i++ {
		binary.LittleEndian.PutUint32(Keystream[(i*mersenneNumberBytes):], m.Uint32())
	}
	return Keystream
}

func doMT(orig []byte, m *MT19937) []byte {
	if m == nil {
		panic("oops")
	}
	var result []byte

	blocks := chunk(orig, MersenneStreamBlockSize)
	for _, block := range blocks {
		Keystream := getMTKeystream(m)
		plain := FlexibleXor(block, Keystream[:len(block)])
		result = append(result, plain...)
	}
	return result
}
