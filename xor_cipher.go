package cryptopals

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"strings"
)

// RepeatingKeyXor sequentially applies each byte of the key to the plaintext and returns the result hex encoded
func RepeatingKeyXor(plain, key string) (string, error) {
	res, err := RepeatingKeyXorBytes([]byte(plain), []byte(key))
	return fmt.Sprintf("%x", res), err
}

func RepeatingKeyXorBytes(p, key []byte) ([]byte, error) {
	b, err := FixedXor(p, RepeatBytesToLegnth(key, len(p)))
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return b, nil
}

func RepeatBytesToLegnth(b []byte, l int) []byte {
	res := [][]byte{bytes.Repeat(b, l/len(b)), b[:l%len(b)]}
	return bytes.Join(res, nil)
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

func DecryptRepeatingKeyXor(b []byte) (PlainText, error) {
	keysizes, err := guessKeysize(b)
	if err != nil {
		return PlainText{}, err
	}
	// fmt.Printf("Best guesses for keysize are %d\n", keysizes)
	var res PlainText
	for i := 0; i < len(keysizes); i++ {
		r, err := DecryptRepeatingKeyXorWithKeysize(b, keysizes[i])
		if err != nil {
			return PlainText{}, err
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

func DecryptRepeatingKeyXorWithKeysize(b []byte, keysize int) (PlainText, error) {
	blocks := chunk(b, keysize)
	t := transpose(blocks, keysize)
	key := make([]string, keysize)
	for i := 0; i < keysize; i++ {
		s, err := SolveSingleByteXorCipher(t[i])
		if err != nil {
			return PlainText{}, err
		}
		key[i] = string(s.key)
	}
	decryptionKey := []byte(strings.Join(key, ""))
	hplain, err := RepeatingKeyXorBytes(b, decryptionKey)
	if err != nil {
		return PlainText{}, err
	}
	// fmt.Printf("Best guess for key of length %d is %s\n", keysize, key)
	return PlainText{key: decryptionKey, plaintext: hplain}, nil
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
