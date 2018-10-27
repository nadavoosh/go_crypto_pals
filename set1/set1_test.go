package set1

import "testing"

func TestHexToBase64(t *testing.T) {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	got := HexToBase64(in)
	if got != want {
		t.Errorf("ToBase64(%q) == %q, want %q", in, got, want)
	}
}

func TestHexFixedXor(t *testing.T) {
	in1 := "1c0111001f010100061a024b53535009181c"
	in2 := "686974207468652062756c6c277320657965"
	want := "746865206b696420646f6e277420706c6179"
	got, err := HexFixedXor(in1, in2)
	if err != nil {
		t.Errorf("ToBase64(%q, %q) threw an error", in1, in2)
	}
	if got != want {
		t.Errorf("ToBase64(%q, %q) == %q, want %q", in1, in2, got, want)
	}
}

func TestSolveSingleByteXorCipher(t *testing.T) {
	in := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	want := "Cooking MC's like a pound of bacon"
	got, err := SolveSingleByteXorCipher(in)
	if err != nil {
		t.Errorf("SolveSingleByteXorCipher(%q) threw an error", in)
	}
	if string(got.text) != want {
		t.Errorf("SolveSingleByteXorCipher(%q) == %q, want %q", in, got.text, want)
	}
}

func TestDetectSingleByteXorCipher(t *testing.T) {
	in := "https://cryptopals.com/static/challenge-data/4.txt"
	want := "Now that the party is jumping\n"
	got, err := DetectSingleByteXorCipher(in)
	if err != nil {
		t.Errorf("DetectSingleByteXorCipher(%q) threw an error", in)
	}
	if string(got.text) != want {
		t.Errorf("DetectSingleByteXorCipher(%q) == %q, want %q", in, got.text, want)
	}
}

func TestEncryptRepeatingKeyXor(t *testing.T) {
	in := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	keyIn := "ICE"
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	got, err := EncryptRepeatingKeyXor(in, keyIn)
	if err != nil {
		t.Errorf("EncryptRepeatingKeyXor(%q) threw an error", in)
	}
	if got != want {
		t.Errorf("EncryptRepeatingKeyXor(%q) == %q, want %q", in, got, want)
	}
}

func TestHemmingDistance(t *testing.T) {
	in, in2 := "this is a test", "wokka wokka!!!"
	want := 37
	got, err := HemmingDistance(in, in2)
	if err != nil {
		t.Errorf("HemmingDistance(%q, %q) threw an error", in, in2)
	}
	if got != want {
		t.Errorf("HemmingDistance(%q, %q) == %d, want %d", in, in2, got, want)
	}
}
