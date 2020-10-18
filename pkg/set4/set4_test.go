package set4

import (
	"testing"

	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

func TestRandomAccessReadWriteAESCTR(t *testing.T) {
	in := utils.HexEncoded{HexString: "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"}
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	got := utils.HexToBase64(in)
	if got != want {
		t.Errorf("ToBase64(%q) == %q, want %q", in, got, want)
	}
}
