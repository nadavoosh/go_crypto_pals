package pals

import (
	"bytes"
	"fmt"

	"github.com/nadavoosh/go_crypto_pals/pkg/padding"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

func buildMap(f EncryptionFn, testInput []byte, blocksize, blockNumber int) (map[string]byte, error) {
	m := make(map[string]byte)
	for i := 0; i < 256; i++ {
		b := append(testInput, byte(i))
		p, err := f(b)
		if err != nil {
			return nil, err
		}
		ret := p[(blockNumber * blocksize) : (blockNumber+1)*blocksize]
		m[string(ret)] = byte(i)
	}
	return m, nil
}

func getPaddingLength(f EncryptionFn, blocksize int) (int, int, error) {
	// Encrypt 3 * blocksize bytes and find the (first) Ciphertext block that is repeated. This is likely our block, encrypted.
	c, err := f(bytes.Repeat(utils.ByteA, 3*blocksize))
	if err != nil {
		return 0, 0, err
	}
	blocks := chunk(c, blocksize)
	var encryptedABytes []byte
	m := make(map[string]int64)
	for _, block := range blocks {
		for _, b := range blocks {
			if testEq(b, block) {
				m[string(block)]++
				if m[string(block)] > 1 {
					encryptedABytes = []byte(block)
					break
				}
			}
		}
	}
	if encryptedABytes == nil {
		return 0, 0, fmt.Errorf("Could not find two identical Ciphertext blocks, something went wrong")
	}
	// now add blocksize + n more bytes, increasing n 1 at a time until the encrypted block we found earlier appears in the Ciphertext again.
	// n bytes of padding will bring the prepended text to a full block, and we can trim it off the Ciphertext.
	for n := 0; n < blocksize; n++ {
		c, err := f(bytes.Repeat(utils.ByteA, blocksize+n))
		if err != nil {
			return 0, 0, err
		}
		blocks = chunk(c, blocksize)
		for i, b := range blocks {
			if testEq(b, encryptedABytes) {
				return n, i, nil
			}
		}
	}
	return 0, 0, fmt.Errorf("Could not create a third identical Ciphertext block, something went wrong")
}

func (o EncryptionOracle) DecryptECBAppend() ([]byte, error) {
	f := o.Encrypt
	blocksize, err := inferBlocksize(f)
	if err != nil {
		return nil, err
	}
	sampleCiphertext, err := f(bytes.Repeat(utils.ByteA, 3*blocksize))
	if err != nil {
		return nil, err
	}
	if !SmellsOfECB(sampleCiphertext) {
		return nil, fmt.Errorf("ECB Mode not detected in Ciphertext")
	}
	baseCiphertext, err := f(nil)
	if err != nil {
		return nil, err
	}
	var nPlain []byte
	// handle any prepended blocks:
	paddingLen, blocksToSkip, err := getPaddingLength(f, blocksize)
	if err != nil {
		return nil, err
	}
	for n := blocksToSkip; n < len(baseCiphertext)/blocksize+1; n++ {
		for j := 0; j < blocksize; j++ {
			baseInput := bytes.Repeat(utils.ByteA, paddingLen+blocksize-(j+1))
			testInput := append(baseInput, nPlain...)
			m, err := buildMap(f, testInput, blocksize, n)
			if err != nil {
				return nil, err
			}
			match, err := f(baseInput)
			if err != nil {
				return nil, err
			}
			if len(match) <= n*blocksize {
				// this happens when j is large enough to cause len(f(baseInput).Ciphertext) to be smaller than the Ciphertexts in the map, since a block-boundary was crossed.
				continue
			}
			actual := match[(n * blocksize) : (n+1)*blocksize]
			if deciphered, ok := m[string(actual)]; ok {
				nPlain = append(nPlain, deciphered)
			} else {
				// fmt.Printf("block %02d, base input len of %02d, test input has len %02d, iteration %02d, with Ciphertext of len %d\n",n, len(baseInput), len(testInput), j, len(match.Ciphertext))
				// fmt.Printf("encrypted string %s not found in decryption map for byte %d\n", actual, j)
				continue
			}
		}
	}
	if nPlain == nil {
		return nil, fmt.Errorf("Found zero encrypted string matches, which is wrong")
	}
	return padding.RemovePKCSPadding(nPlain), nil
}
