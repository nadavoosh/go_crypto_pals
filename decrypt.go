package set1

import ()

// // DecryptRepeatingKeyXor
// func DecryptRepeatingKeyXor(cipher string) (string, error) {

// 	return "", nil
// }

// func guessKeysize(b []byte) {
// 	for keysize := 2; keysize < 40; keysize++ {
// 	}
// }

// HemmingDistance returns the number of differing bits in two equal length strings
func HemmingDistance(s1, s2 string) (int, error) {
	var score int
	b1, b2 := []byte(s1), []byte(s2)
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
