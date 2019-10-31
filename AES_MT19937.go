package cryptopals

import (
	"crypto/aes"
	"encoding/binary"
)

func seedFromKeyD(d PlainText) {
	d.MT = NewMersenneTwister()
	d.MT.Seed(int(binary.BigEndian.Uint64(d.key)))
}

func seedFromKeyE(e EncryptedText) {
	e.MT = NewMersenneTwister()
	e.MT.Seed(int(binary.BigEndian.Uint64(e.key)))
}

func encryptMT(d PlainText) (EncryptedText, error) {
	return EncryptedText{key: d.key, ciphertext: doMT(d.plaintext, d.MT)}, nil
}

func decryptMT(e EncryptedText) (PlainText, error) {
	return PlainText{key: e.key, plaintext: doMT(e.ciphertext, e.MT)}, nil
}

func doMT(orig []byte, m *MT19937) []byte {
	if m == nil {
		panic("oops")
	}
	var result []byte
	blocks := chunk(orig, aes.BlockSize)
	for _, block := range blocks {
		keystream := make([]byte, 32)
		binary.LittleEndian.PutUint32(keystream, m.Uint32())
		trimmedKeystream := keystream[:len(block)]
		plain := FlexibleXor(block, trimmedKeystream)
		result = append(result, plain...)
	}
	return result
}
