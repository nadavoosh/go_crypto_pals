package set1

import (
	// "fmt"
	"log"
	"regexp"
	"strings"
)

// SolveSingleByteXorCipher examines the input XORed against a single character, and returns the most likely original text and key, based on english character frequency
func SolveSingleByteXorCipher(h string) (string, error) {
	minScore := float64(1000000)
	var res string
	var newScore float64
	hBytes := HexToBytes(h)
	for i := byte(0); i < 255; i++ {
		tprime, err := singleByteXor(hBytes, i)
		if err != nil {
			log.Fatal(err)
		}
		newScore = getScore(tprime)
		if newScore < minScore {
			minScore = newScore
			res = string(tprime)
		}
	}
	return res, nil
}

func singleByteXor(h []byte, c byte) ([]byte, error) {
	repeated := make([]byte, len(h))
	for i := 0; i < len(h); i++ {
		repeated[i] = c
	}
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
	// 10 point penalty for every non alphabetical character other than space
	score := float64(len(string(text))-len(alphabetical)) * 10
	lowerText := strings.ToLower(string(alphabetical))

	m := getLetterFreqMapForEnglish()
	total := float64(len(lowerText))
	for char, value := range m {
		s = (float64(strings.Count(lowerText, char))/total*100 - value)
		score += s * s
	}
	return score
}
