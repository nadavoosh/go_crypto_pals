package set1

import (
	"bufio"
	// "fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
)

type HumanText interface {
	score() float64
}

type DecryptionResult struct {
	key       string
	plaintext string
}

func GetScore(text []byte) float64 {
	return getScore(text)
}

func (d DecryptionResult) score() float64 {
	if d.plaintext == "" {
		// return a high score for uninitialized DecryptionResult
		return float64(1e10)
	}
	return getScore([]byte(d.plaintext))
}

// SolveSingleByteXorCipherHex examines the input XORed against a single character, and returns the most likely original text and key, based on english character frequency
func SolveSingleByteXorCipherHex(h string) (DecryptionResult, error) {
	hBytes := HexToBytes(h)
	return SolveSingleByteXorCipher(hBytes)
}

// SolveSingleByteXorCipher examines the input XORed against a single character, and returns the most likely original text and key, based on english character frequency
func SolveSingleByteXorCipher(hBytes []byte) (DecryptionResult, error) {
	var res DecryptionResult
	var newScore float64
	for i := byte(0); i < 255; i++ {
		t, err := singleByteXor(hBytes, i)
		if err != nil {
			log.Fatal(err)
		}
		tprime := DecryptionResult{plaintext: string(t), key: string(i)}
		newScore = tprime.score()
		if newScore < res.score() {
			res = tprime
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
	// 1000 point penalty for every non alphabetical character other than space
	// fmt.Printf("Now scoring %s\n", string(text))

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

func DetectSingleByteXorCipher(url string) (DecryptionResult, error) {
	lines, err := UrlToLines(url)
	var res DecryptionResult
	if err != nil {
		return res, err
	}
	for _, h := range lines {
		s, err := SolveSingleByteXorCipherHex(h)
		if err != nil {
			return s, err
		}
		if s.score() < res.score() {
			res = s
		}
	}
	return res, nil
}

func UrlToLines(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return LinesFromReader(resp.Body)
}

func LinesFromReader(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}
