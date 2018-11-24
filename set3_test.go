package cryptopals

import (
	"testing"
)

func TestCBCPadding(t *testing.T) {
	in := HexEncoded{hexString: "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"}
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	got := HexToBase64(in)
	if got != want {
		t.Errorf("ToBase64(%q) == %q, want %q", in, got, want)
	}
}
