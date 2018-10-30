package set1

import (
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
)

func DecryptRepeatingKeyXorFromBase64(filename string) (DecryptionResult, error) {
	lines, err := ScanFile(filename)
	if err != nil {
		return DecryptionResult{}, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	if err != nil {
		return DecryptionResult{}, err
	}
	return DecryptRepeatingKeyXorHex(HexEncoded{hexString: fmt.Sprintf("%0x", decoded)})
}

func chunk(b []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(b); i += chunkSize {
		end := i + chunkSize
		if end > len(b) {
			end = len(b)
		}
		chunks = append(chunks, b[i:end])
	}
	return chunks
}

func DecryptRepeatingKeyXorHex(hexCipher HexEncoded) (DecryptionResult, error) {
	return decryptRepeatingKeyXor(hexCipher.getBytes())
}

func decryptRepeatingKeyXor(b []byte) (DecryptionResult, error) {
	keysizes, err := guessKeysize(b)
	if err != nil {
		return DecryptionResult{}, err
	}
	// fmt.Printf("Best guesses for keysize are %d\n", keysizes)
	var res DecryptionResult
	for i := 0; i < len(keysizes); i++ {
		r, err := DecryptRepeatingKeyXorWithKeysize(b, keysizes[i])
		if err != nil {
			return DecryptionResult{}, err
		}
		if r.score() < res.score() {
			res = r
		}
	}
	return res, nil
}

func transpose(b [][]byte, keysize int) [][]byte {
	transposed := make([][]byte, keysize)
	for _, block := range b {
		for i := 0; i < keysize; i++ {
			if len(block) > i {
				transposed[i] = append(transposed[i], block[i])
			}

		}
	}
	return transposed
}

func DecryptRepeatingKeyXorWithKeysize(b []byte, keysize int) (DecryptionResult, error) {
	blocks := chunk(b, keysize)
	t := transpose(blocks, keysize)
	key := make([]string, keysize)
	for i := 0; i < keysize; i++ {
		s, err := SolveSingleByteXorCipher(t[i])
		if err != nil {
			return DecryptionResult{}, err
		}
		key[i] = string(s.key)
	}
	decryptionKey := strings.Join(key, "")
	hplain, err := RepeatingKeyXorBytes(b, []byte(decryptionKey))
	if err != nil {
		return DecryptionResult{}, err
	}
	// fmt.Printf("Best guess for key of length %d is %s\n", keysize, decryptionKey)
	return DecryptionResult{key: decryptionKey, plaintext: string(hplain)}, nil
}

func guessKeysize(b []byte) ([]int, error) {
	return guessKeysizeAveraged(b, 4)
}

func guessKeysizeBasic(b []byte) (int, error) {
	var keyGuess int
	minScore := float64(1000000)
	for keysize := 2; keysize < 40; keysize++ {
		newScore, err := hemmingDistanceBytes(b[:keysize], b[keysize:keysize*2])
		if err != nil {
			log.Fatal(err)
			return keyGuess, err
		}
		normalized := float64(newScore) / float64(keysize)
		// fmt.Printf("keysize of %d has score of %f\n", keysize, normalized)
		if normalized < minScore {
			minScore = normalized
			keyGuess = keysize
		}
	}
	return keyGuess, nil
}

func getKeysFromMap(m map[int]float64) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func guessKeysizeAveraged(b []byte, numBlocks int) ([]int, error) {
	keyGuessesMap := make(map[int]float64)
	var highestScoringKeysizeInMap int
	if numBlocks < 2 {
		return nil, errors.New("Need at least 2 blocks to compare")
	}
	for keysize := 1; keysize < 40; keysize++ {
		var newScore int
		for i := 0; i < (numBlocks - 1); i++ {
			s, err := hemmingDistanceBytes(b[keysize*i:keysize*(i+1)], b[keysize*(i+1):keysize*(i+2)])
			if err != nil {
				log.Fatal(err)
				return nil, err
			}
			newScore += s
		}
		normalized := float64(newScore) / float64(keysize) / float64(numBlocks-1)
		// fmt.Printf("keysize of %d has score of %f\n", keysize, normalized)
		NumberOfKeyGuessesToReturn := 3
		if len(keyGuessesMap) < NumberOfKeyGuessesToReturn {
			// fmt.Printf("Initializing by adding key %b with score %g\n", keysize, normalized)
			keyGuessesMap[keysize] = normalized
		} else {
			if normalized < keyGuessesMap[highestScoringKeysizeInMap] {
				// fmt.Printf("%g is lower than %g so adding %b and removing %b\n", normalized, keyGuessesMap[highestScoringKeysizeInMap], keysize, highestScoringKeysizeInMap)
				delete(keyGuessesMap, highestScoringKeysizeInMap)
				keyGuessesMap[keysize] = normalized
			}
		}
		var newhighestScoringKeysizeInMap float64
		for k, v := range keyGuessesMap {
			if v > newhighestScoringKeysizeInMap {
				// fmt.Printf("%g is higher than %g so setting %b to highest key in map\n", v, newhighestScoringKeysizeInMap, k)
				newhighestScoringKeysizeInMap = v
				highestScoringKeysizeInMap = k
			}
		}
		// fmt.Printf("highestScoringKeysizeInMap is %b at %g\n", highestScoringKeysizeInMap, keyGuessesMap[highestScoringKeysizeInMap])
	}
	return getKeysFromMap(keyGuessesMap), nil
}

// HemmingDistance returns the number of differing bits in two equal length strings
func HemmingDistance(s1, s2 string) (int, error) {
	return hemmingDistanceBytes([]byte(s1), []byte(s2))
}

func hemmingDistanceBytes(b1, b2 []byte) (int, error) {
	var score int
	if err := AssertEqualLen(b1, b2); err != nil {
		return 0, err
	}
	for i := range b1 {
		score += bitsDifferent(b1[i], b2[i])
	}
	return score, nil
}

func bitsDifferent(b1, b2 byte) int {
	var diff int
	for j := 0; j < 8; j++ {
		mask := byte(1 << uint(j))
		if (b1 & mask) != (b2 & mask) {
			diff++
		}
	}
	return diff
}
func Decrypt_AES_ECB_FromBase64File(filename, encryptionKey string) (DecryptionResult, error) {
	lines, err := ScanFile(filename)
	if err != nil {
		return DecryptionResult{}, err
	}
	return Decrypt_AES_ECB(strings.Join(lines, ""), encryptionKey)
}

func Decrypt_AES_ECB(ciphertext, encryptionKey string) (DecryptionResult, error) {
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return DecryptionResult{}, err
	}
	cipher, err := aes.NewCipher([]byte(encryptionKey))
	if err != nil {
		return DecryptionResult{}, err
	}
	var plaintext []byte
	blocks := chunk([]byte(decoded), aes.BlockSize)
	for _, block := range blocks {
		dst := make([]byte, aes.BlockSize)
		cipher.Decrypt(dst, block)
		plaintext = append(plaintext, dst...)
	}

	return DecryptionResult{plaintext: string(plaintext)}, nil
}

func testEq(a, b []byte) bool {
	// If one is nil, the other must also be nil.
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func smellsOfECB(b []byte) bool {
	blocks := chunk(b, aes.BlockSize)
	for _, block := range blocks {
		count := 0
		for _, b := range blocks {
			if testEq(b, block) {
				count++
			}
		}
		if count > 1 {
			return true
		}
	}
	return false
}

func DetectAESinECBFromFile(filename string) ([]HexEncoded, error) {
	lines, err := ScanFile(filename)
	var ECBs []HexEncoded
	if err != nil {
		return nil, err
	}

	for _, l := range lines {
		h := HexEncoded{hexString: l}
		if smellsOfECB(h.getBytes()) {
			// fmt.Printf("%s seemss like it was encrypted with ECB\n", h)
			ECBs = append(ECBs, h)
		}
	}
	return ECBs, nil
}
