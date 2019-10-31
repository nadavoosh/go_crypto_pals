package cryptopals

import (
	"log"
	"regexp"
	"strings"
)

type CryptoMaterial struct {
	key   []byte
	iv    []byte
	nonce int64
	MT    *MT19937
}

type EncryptedText struct {
	CryptoMaterial
	ciphertext []byte
	padding    Padding
}

type PlainText struct {
	CryptoMaterial
	plaintext []byte
}

func (d PlainText) score() float64 {
	if d.plaintext == nil {
		// return a high score for uninitialized PlainText
		return float64(1e10)
	}
	return getScore([]byte(d.plaintext))
}

func (d PlainText) minimize() float64 {
	if d.plaintext == nil {
		// return a high score for uninitialized PlainText
		return float64(1e10)
	}
	return getScore([]byte(d.plaintext))
}

// SolveSingleByteXorCipherHex examines the input XORed against a single character, and returns the most likely original text and key, based on english character frequency
func SolveSingleByteXorCipherHex(h HexEncoded) (PlainText, error) {
	return SolveSingleByteXorCipher(h.getBytes())
}

// SolveSingleByteXorCipher examines the input XORed against a single character, and returns the most likely original text and key, based on english character frequency
func SolveSingleByteXorCipher(hBytes []byte) (PlainText, error) {
	var res PlainText
	var newScore float64
	for i := 0; i < 256; i++ {
		t, err := singleByteXor(hBytes, byte(i))
		if err != nil {
			log.Fatal(err)
		}
		tprime := PlainText{plaintext: t, CryptoMaterial: CryptoMaterial{key: []byte{byte(i)}}}
		newScore = tprime.score()
		if newScore < res.score() {
			res = tprime
		}
	}
	return res, nil
}

func FillByteSlice(l int, c byte) []byte {
	repeated := make([]byte, l)
	for i := 0; i < l; i++ {
		repeated[i] = c
	}
	return repeated
}

func singleByteXor(h []byte, c byte) ([]byte, error) {
	repeated := FillByteSlice(len(h), c)
	return FixedXor(h, repeated)
}

func getLetterFreqMapForEnglish() map[string]float64 {
	// https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
	m := make(map[string]float64)
	m["a"] = 8.167
	m["b"] = 1.492
	m["c"] = 2.782
	m["d"] = 4.253
	m["e"] = 12.702
	m["f"] = 2.228
	m["g"] = 2.015
	m["h"] = 6.094
	m["i"] = 6.966
	m["j"] = 0.153
	m["k"] = 0.772
	m["l"] = 4.025
	m["m"] = 2.406
	m["n"] = 6.749
	m["o"] = 7.507
	m["p"] = 1.929
	m["q"] = 0.095
	m["r"] = 5.987
	m["s"] = 6.327
	m["t"] = 9.056
	m["u"] = 2.758
	m["v"] = 0.978
	m["w"] = 2.360
	m["x"] = 0.150
	m["y"] = 1.974
	m["z"] = 0.074
	return m
}

func getScore(text []byte) float64 {
	// lower score is more likely to be english
	var s float64
	a, err := regexp.Compile("[^a-zA-Z ]")
	if err != nil {
		log.Fatal(err)
	}
	alphabetical := a.ReplaceAllString(string(text), "")
	// 1000 point penalty for every non alphabetical character other than space
	score := float64(len(string(text))-len(alphabetical)) * 1000
	lowerText := strings.ToLower(string(alphabetical))

	if len(lowerText) > 0 {
		m := getLetterFreqMapForEnglish()
		total := float64(len(lowerText))
		for char, value := range m {
			s = (float64(strings.Count(lowerText, char))/total*100 - value)
			score += s * s
		}
	}
	return score
}

func DetectSingleByteXorCipher(lines []string) (PlainText, error) {
	var res PlainText
	for _, h := range lines {
		s, err := SolveSingleByteXorCipherHex(HexEncoded{hexString: h})
		if err != nil {
			return s, err
		}
		if s.score() < res.score() {
			res = s
		}
	}
	return res, nil
}
