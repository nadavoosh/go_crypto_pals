package cryptopals

import (
	"encoding/binary"
)

const mersenneStreamBlockSize = 8

func seedFromKeyD(d *PlainText) {
	d.MT = NewMersenneTwister()
	d.MT.Seed(int(binary.BigEndian.Uint16(d.key)))
}

func seedFromKeyE(e *EncryptedText) {
	e.MT = NewMersenneTwister()
	e.MT.Seed(int(binary.BigEndian.Uint16(e.key)))
}

func encryptMT(d PlainText) (EncryptedText, error) {
	seedFromKeyD(&d)
	return EncryptedText{CryptoMaterial: CryptoMaterial{key: d.key}, ciphertext: doMT(d.plaintext, d.MT)}, nil
}

func decryptMT(e EncryptedText) (PlainText, error) {
	seedFromKeyE(&e)
	return PlainText{CryptoMaterial: CryptoMaterial{key: e.key}, plaintext: doMT(e.ciphertext, e.MT)}, nil
}

func getMTKeystream(m *MT19937) []byte {
	keystream := make([]byte, mersenneStreamBlockSize)
	for i := 0; i < mersenneStreamBlockSize/4; i++ {
		binary.LittleEndian.PutUint32(keystream[(i*4):], m.Uint32())
	}
	return keystream
}

func doMT(orig []byte, m *MT19937) []byte {
	if m == nil {
		panic("oops")
	}
	var result []byte

	blocks := chunk(orig, mersenneStreamBlockSize)
	for _, block := range blocks {
		keystream := getMTKeystream(m)
		plain := FlexibleXor(block, keystream[:len(block)])
		result = append(result, plain...)
	}
	return result
}
