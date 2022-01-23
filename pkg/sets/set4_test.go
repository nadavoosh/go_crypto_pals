package sets

import (
	"strings"
	"testing"

	"github.com/nadavoosh/go_crypto_pals/pkg/pals"
	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

func TestRandomAccessReadWriteAESCTR(t *testing.T) {
	filename := "../../challenges/challenge25.txt"
	lines, err := utils.ScanFile(filename)
	if err != nil {
		t.Errorf("ScanFile(%q) threw an error: %s", filename, err)
	}
	decoded, err := utils.ParseBase64(strings.Join(lines, ""))
	decrypted, err := pals.AES_ECB{Ciphertext: decoded}.Decrypt([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Errorf("ReadBase64File threw an error: %s", err)
		return
	}
	key := utils.GenerateKey()
	e, err := pals.CTR{Plaintext: decrypted}.Encrypt(key)
	if err != nil {
		t.Errorf("CTR Encrypt threw an error: %s", err)
		return
	}
	got, err := breakRandomAccessReadWriteAESCTR(e, key)
	if err != nil {
		t.Errorf("breakRandomAccessReadWriteAESCTR threw an error: %s", err)
		return
	}
	if string(got) != string(decrypted) {
		t.Errorf("breakRandomAccessReadWriteAESCTR didn't work")
	}
}

func TestCTRBitflipping(t *testing.T) {
	in := []byte(";admin=true")
	flipped := flipBitsToHide(in)
	userData, err := encryptUserDataCTR(flipped)
	if err != nil {
		t.Errorf("encryptUserDataCTR threw an error: %s", err)
		return
	}
	b, err := modifyCiphertextForAdmin(userData)
	if err != nil {
		t.Errorf("ModifyCiphertextForAdmin threw an error: %s", err)
		return
	}
	admin, err := detectAdminStringCTR(b)
	if err != nil {
		t.Errorf("detectAdminStringCTR(f) threw an error: %s", err)
		return
	}
	if !admin {
		t.Errorf("detectAdminStringCTR incorrectly missed the admin string for: %s", in)
	}
}

func SkipTestKeyRecoveryfromCBCwithIVEqualToKey(t *testing.T) {
	data := []byte("NADAVRECCANADAVRECCANADAVRECCA")
	_, err := encryptUserDataCBCWithKeyIV(data)
	if err != nil {
		t.Errorf("encryptUserDataCBCWithKeyIV threw an error: %s", err)
		return
	}
}
