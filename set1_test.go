package set1

import "testing"

func TestHexToBase64(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d", "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"},
	}
	for _, c := range cases {
		got := HexToBase64(c.in)
		if got != c.want {
			t.Errorf("ToBase64(%q) == %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHexFixedXor(t *testing.T) {
	cases := []struct {
		in1, in2, want string
	}{
		{"1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965", "746865206b696420646f6e277420706c6179"},
	}
	for _, c := range cases {
		got, err := HexFixedXor(c.in1, c.in2)
		if err != nil {
			t.Errorf("ToBase64(%q, %q) threw an error", c.in1, c.in2)
		}
		if got != c.want {
			t.Errorf("ToBase64(%q, %q) == %q, want %q", c.in1, c.in2, got, c.want)
		}
	}
}

func TestSolveSingleByteXorCipher(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", "Cooking MC's like a pound of bacon"},
	}
	for _, c := range cases {
		got, err := SolveSingleByteXorCipher(c.in)
		if err != nil {
			t.Errorf("SolveSingleByteXorCipher(%q) threw an error", c.in)
		}
		if string(got.text) != c.want {
			t.Errorf("SolveSingleByteXorCipher(%q) == %q, want %q", c.in, got.text, c.want)
		}
	}
}

func TestDetectSingleByteXorCipher(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://cryptopals.com/static/challenge-data/4.txt", "Now that the party is jumping\n"},
	}
	for _, c := range cases {
		got, err := DetectSingleByteXorCipher(c.in)
		if err != nil {
			t.Errorf("DetectSingleByteXorCipher(%q) threw an error", c.in)
		}
		if string(got.text) != c.want {
			t.Errorf("DetectSingleByteXorCipher(%q) == %q, want %q", c.in, got.text, c.want)
		}
	}
}
