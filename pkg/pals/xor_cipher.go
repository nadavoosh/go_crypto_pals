package pals

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

// RepeatingKeyXor sequentially applies each byte of the Key to the Plaintext and returns the result hex encoded
func RepeatingKeyXor(plain, Key string) (string, error) {
	res, err := RepeatingKeyXorBytes([]byte(plain), []byte(Key))
	return fmt.Sprintf("%x", res), err
}

func RepeatingKeyXorBytes(p, Key []byte) ([]byte, error) {
	b, err := utils.FixedXor(p, RepeatBytesToLegnth(Key, len(p)))
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

func Chunk(b []byte, chunkSize int) [][]byte {
	return chunk(b, chunkSize)
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

func DecryptRepeatingKeyXor(b []byte) (PlainText, Key, error) {
	Keysizes, err := guessKeysize(b)
	if err != nil {
		return PlainText{}, nil, err
	}
	// fmt.Printf("Best guesses for Keysize are %d\n", Keysizes)
	var res PlainText
	var resKey Key
	for i := 0; i < len(Keysizes); i++ {
		r, k, err := DecryptRepeatingKeyXorWithKeysize(b, Keysizes[i])
		if err != nil {
			return PlainText{}, nil, err
		}
		if r.score() < res.score() {
			res = r
			resKey = k
		}
	}
	return res, resKey, nil
}

func transpose(b [][]byte, Keysize int) [][]byte {
	transposed := make([][]byte, Keysize)
	for _, block := range b {
		for i := 0; i < Keysize; i++ {
			if len(block) > i {
				transposed[i] = append(transposed[i], block[i])
			}

		}
	}
	return transposed
}

func DecryptRepeatingKeyXorWithKeysize(b []byte, Keysize int) (PlainText, Key, error) {
	blocks := chunk(b, Keysize)
	t := transpose(blocks, Keysize)
	Key := make([]string, Keysize)
	for i := 0; i < Keysize; i++ {
		_, k, err := SolveSingleByteXorCipher(t[i])
		if err != nil {
			return PlainText{}, nil, err
		}
		Key[i] = string(k)
	}
	decryptionKey := []byte(strings.Join(Key, ""))
	hplain, err := RepeatingKeyXorBytes(b, decryptionKey)
	if err != nil {
		return PlainText{}, nil, err
	}
	// fmt.Printf("Best guess for Key of length %d is %s\n", Keysize, Key)
	return PlainText{Plaintext: hplain}, decryptionKey, nil
}

func guessKeysize(b []byte) ([]int, error) {
	return guessKeysizeAveraged(b, 4)
}

func guessKeysizeBasic(b []byte) (int, error) {
	var KeyGuess int
	minScore := float64(1000000)
	for Keysize := 2; Keysize < 40; Keysize++ {
		newScore, err := hemmingDistanceBytes(b[:Keysize], b[Keysize:Keysize*2])
		if err != nil {
			log.Fatal(err)
			return KeyGuess, err
		}
		normalized := float64(newScore) / float64(Keysize)
		// fmt.Printf("Keysize of %d has score of %f\n", Keysize, normalized)
		if normalized < minScore {
			minScore = normalized
			KeyGuess = Keysize
		}
	}
	return KeyGuess, nil
}

func getKeysFromMap(m map[int]float64) []int {
	Keys := make([]int, 0, len(m))
	for k := range m {
		Keys = append(Keys, k)
	}
	return Keys
}

func guessKeysizeAveraged(b []byte, numBlocks int) ([]int, error) {
	KeyGuessesMap := make(map[int]float64)
	var highestScoringKeysizeInMap int
	if numBlocks < 2 {
		return nil, errors.New("Need at least 2 blocks to compare")
	}
	for Keysize := 1; Keysize < 40; Keysize++ {
		var newScore int
		for i := 0; i < (numBlocks - 1); i++ {
			s, err := hemmingDistanceBytes(b[Keysize*i:Keysize*(i+1)], b[Keysize*(i+1):Keysize*(i+2)])
			if err != nil {
				log.Fatal(err)
				return nil, err
			}
			newScore += s
		}
		normalized := float64(newScore) / float64(Keysize) / float64(numBlocks-1)
		// fmt.Printf("Keysize of %d has score of %f\n", Keysize, normalized)
		NumberOfKeyGuessesToReturn := 3
		if len(KeyGuessesMap) < NumberOfKeyGuessesToReturn {
			// fmt.Printf("Initializing by adding Key %b with score %g\n", Keysize, normalized)
			KeyGuessesMap[Keysize] = normalized
		} else {
			if normalized < KeyGuessesMap[highestScoringKeysizeInMap] {
				// fmt.Printf("%g is lower than %g so adding %b and removing %b\n", normalized, KeyGuessesMap[highestScoringKeysizeInMap], Keysize, highestScoringKeysizeInMap)
				delete(KeyGuessesMap, highestScoringKeysizeInMap)
				KeyGuessesMap[Keysize] = normalized
			}
		}
		var newhighestScoringKeysizeInMap float64
		for k, v := range KeyGuessesMap {
			if v > newhighestScoringKeysizeInMap {
				// fmt.Printf("%g is higher than %g so setting %b to highest Key in map\n", v, newhighestScoringKeysizeInMap, k)
				newhighestScoringKeysizeInMap = v
				highestScoringKeysizeInMap = k
			}
		}
		// fmt.Printf("highestScoringKeysizeInMap is %b at %g\n", highestScoringKeysizeInMap, KeyGuessesMap[highestScoringKeysizeInMap])
	}
	return getKeysFromMap(KeyGuessesMap), nil
}

// HemmingDistance returns the number of differing bits in two equal length strings
func HemmingDistance(s1, s2 string) (int, error) {
	return hemmingDistanceBytes([]byte(s1), []byte(s2))
}

func hemmingDistanceBytes(b1, b2 []byte) (int, error) {
	var score int
	if err := utils.AssertEqualLen(b1, b2); err != nil {
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

func TestEq(a, b []byte) bool {
	return testEq(a, b)
}
