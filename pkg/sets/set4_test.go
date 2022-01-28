package sets

import (
	"bytes"
	// "fmt"
	"regexp"
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

func TestKeyRecoveryfromCBCwithIVEqualToKey(t *testing.T) {
	data := []byte("NADAVRECCANADAVRECCANADAVRECCA")
	c, err := encryptCBCWithKeyIV(data)
	if err != nil {
		t.Errorf("encryptUserDataCBCWithKeyIV threw an error: %s", err)
		return
	}
	blocksize := 16
	// Modify the message (you are now the attacker):
	// C_1, C_2, C_3 -> C_1, 0, C_1
	attackerMessage := append(append(c[:blocksize], bytes.Repeat([]byte{0}, blocksize)...), c[:blocksize]...)
	// Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found
	_, err = decryptCBCWithKeyIV(attackerMessage)
	if err == nil {
		t.Errorf("SkipTestKeyRecoveryfromCBCwithIVEqualToKey didn't work")
	}
	re1 := regexp.MustCompile(`Error, invalid values found in user input: (.*?)$`)
	result_slice := re1.FindStringSubmatch(err.Error())
	// P'_1 XOR P'_3
	res := []byte(result_slice[1])
	key, err := utils.FixedXor(res[:blocksize], res[blocksize*2:blocksize*3])
	if err != nil {
		t.Errorf("utils.FixedXor threw an error: %s", err)
		return
	}
	if string(key) != string(utils.FixedKey) {
		t.Errorf("SkipTestKeyRecoveryfromCBCwithIVEqualToKey didn't work")
	}
}

func TestSha1KeyedMAC(t *testing.T) {
	mac := secretPrefixMAC([]byte("NADAV"))
	if verifySecretPrefixMAC([]byte("VADAN"), mac) {
		t.Errorf("we have an issue with TestSha1KeyedMAC")
	}
}

func TestForgeSha1KeyedMAC(t *testing.T) {
	mac := secretPrefixMAC([]byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"))
	if verifySecretPrefixMAC([]byte("VADAN"), mac) {
		t.Errorf("we have an issue with TestSha1KeyedMAC")
	}
}
