package set1

import (
	"strings"
	"testing"

	"github.com/nadavoosh/go_crypto_pals/pkg/pals"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

func TestHexToBase64(t *testing.T) {
	in := utils.HexEncoded{HexString: "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"}
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	got := utils.HexToBase64(in)
	if got != want {
		t.Errorf("ToBase64(%q) == %q, want %q", in, got, want)
	}
}

func TestHexFixedXor(t *testing.T) {
	in1 := utils.HexEncoded{HexString: "1c0111001f010100061a024b53535009181c"}
	in2 := utils.HexEncoded{HexString: "686974207468652062756c6c277320657965"}
	want := "746865206b696420646f6e277420706c6179"
	got, err := utils.HexFixedXor(in1, in2)
	if err != nil {
		t.Errorf("ToBase64(%q, %q) threw an error", in1, in2)
	}
	if got != want {
		t.Errorf("ToBase64(%q, %q) == %q, want %q", in1, in2, got, want)
	}
}

func TestSolveSingleByteXorCipherHex(t *testing.T) {
	in := utils.HexEncoded{HexString: "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"}
	want := "Cooking MC's like a pound of bacon"
	alsoWant := "X"
	got, gotkey, err := pals.SolveSingleByteXorCipherHex(in)
	if err != nil {
		t.Errorf("SolveSingleByteXorCipherHex(%q) threw an error", in)
	}
	if string(got) != want {
		t.Errorf("SolveSingleByteXorCipherHex(%q) == %q, want %q", in, got, want)
	}
	if string(gotkey) != alsoWant {
		t.Errorf("SolveSingleByteXorCipherHex(%q) == %q, want %q", in, gotkey, alsoWant)
	}
}

func TestDetectSingleByteXorCipher(t *testing.T) {
	filename := "../../challenges/challenge4.txt"
	want := "Now that the party is jumping\n"
	lines, err := utils.ScanFile(filename)
	if err != nil {
		t.Errorf("ScanFile(%q) threw an error", filename)
	}
	got, err := pals.DetectSingleByteXorCipher(lines)
	if err != nil {
		t.Errorf("DetectSingleByteXorCipher(%q) threw an error", filename)
	}
	if string(got) != want {
		t.Errorf("DetectSingleByteXorCipher(%q) == %q, want %q", lines, got, want)
	}
}

func TestRepeatingKeyXor(t *testing.T) {
	in := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	KeyIn := "ICE"
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	got, err := pals.RepeatingKeyXor(in, KeyIn)
	if err != nil {
		t.Errorf("RepeatingKeyXor(%q) threw an error", in)
	}
	if got != want {
		t.Errorf("RepeatingKeyXor(%q) == %q, want %q", in, got, want)
	}
}

func TestHemmingDistance(t *testing.T) {
	in, in2 := "this is a test", "wokka wokka!!!"
	want := 37
	got, err := pals.HemmingDistance(in, in2)
	if err != nil {
		t.Errorf("HemmingDistance(%q, %q) threw an error", in, in2)
	}
	if got != want {
		t.Errorf("HemmingDistance(%q, %q) == %d, want %d", in, in2, got, want)
	}
}

func TestDecryptRepeatingKeyXor(t *testing.T) {
	filename := "../../challenges/challenge6.txt"
	wantKey := "Terminator X: Bring the noise"
	lines, err := utils.ReadBase64File(filename)
	if err != nil {
		t.Errorf("ReadBase64File(%q) threw an error: %s", filename, err)
	}
	got, gotKey, err := pals.DecryptRepeatingKeyXor(lines)
	if err != nil {
		t.Errorf("DecryptRepeatingKeyXorFromBase64(%q) threw an error: %s", lines, err)
	}
	if string(gotKey) != wantKey {
		t.Errorf("DecryptRepeatingKeyXorFromBase64(input) == %q, want %q", gotKey, wantKey)
	}
	if string(got) != FunkyMusicUnpadded {
		t.Errorf("DecryptRepeatingKeyXorFromBase64(input) == %q, want %q", got, FunkyMusicUnpadded)
	}
}

func TestDecrypt_AES_ECB_FromBase64File(t *testing.T) {
	filename := "../../challenges/challenge7.txt"
	lines, err := utils.ScanFile(filename)
	if err != nil {
		t.Errorf("ScanFile(%q) threw an error: %s", filename, err)
	}
	key := "YELLOW SUBMARINE"
	decoded, err := utils.ParseBase64(strings.Join(lines, ""))
	got, err := pals.AES_ECB{Ciphertext: decoded}.Decrypt([]byte(key))
	if err != nil {
		t.Errorf("Decrypt_AES_ECB_b64(input) threw an error: %s", err)
	}
	if string(got) != FunkyMusicPadded {
		t.Errorf("Decrypt_AES_ECB_b64(input) == %q, want %q", got, FunkyMusicPadded)
	}
}

func TestDetectECBModeFromFile(t *testing.T) {
	filename := "../../challenges/challenge8.txt"
	want := "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
	lines, err := utils.ScanFile(filename)
	if err != nil {
		t.Errorf("ScanFile(%q) threw an error: %s", filename, err)
	}
	var ECBs []utils.HexEncoded
	for _, l := range lines {
		h := utils.HexEncoded{HexString: l}
		if pals.SmellsOfECB(h.GetBytes()) {
			ECBs = append(ECBs, h)
		}
	}
	if err != nil {
		t.Errorf("DetectECBMode(%q) threw an error: %s", filename, err)
	}
	if len(ECBs) == 0 {
		t.Errorf("DetectECBMode(%q) returned 0 results, want 1", filename)
	} else if len(ECBs) > 1 {
		t.Errorf("DetectECBMode(%q) returned %d results, want 1", filename, len(ECBs))

	} else {
		if ECBs[0].HexString != want {
			t.Errorf("DetectECBMode(%q) == %q, want %q", filename, ECBs, want)
		}
	}
}
