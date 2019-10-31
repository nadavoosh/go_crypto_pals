package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	mathRand "math/rand"
)

type AESMode int

const (
	ECB AESMode = 0
	CBC AESMode = 1
	CTC AESMode = 2
	MT  AESMode = 3
)

func Encrypt(mode AESMode, d PlainText) (EncryptedText, error) {
	switch mode {
	case ECB:
		return encryptECB(d)
	case CBC:
		if d.iv == nil {
			iv, err := generateRandomBlock()
			if err != nil {
				return EncryptedText{}, err
			}
			d.iv = iv
		}
		return encryptCBC(d)
	case CTC:
		return encryptCTC(d)
	case MT:
		return encryptMT(d)
	default:
		return EncryptedText{}, fmt.Errorf("Mode %d unknown", mode)
	}
}

func Decrypt(mode AESMode, e EncryptedText) (PlainText, error) {
	switch mode {
	case ECB:
		return decryptECB(e)
	case CBC:
		if e.iv == nil {
			iv, err := generateRandomBlock()
			if err != nil {
				return PlainText{}, err
			}
			e.iv = iv
		}
		return decryptCBC(e)
	case CTC:
		return decryptCTC(e)
	case MT:
		return decryptMT(e)
	default:
		return PlainText{}, fmt.Errorf("Mode %d unknown", mode)
	}
}

func encryptSingleBlock(cipher cipher.Block, plaintext []byte) []byte {
	dst := make([]byte, aes.BlockSize)
	cipher.Encrypt(dst, plaintext)
	return dst
}

func decryptSingleBlock(cipher cipher.Block, ciphertext []byte) []byte {
	dst := make([]byte, aes.BlockSize)
	cipher.Decrypt(dst, ciphertext)
	return dst
}

func generateRandomBlock() ([]byte, error) {
	key := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	return key, err
}

func addRandomBytes(p []byte) ([]byte, error) {
	lenBefore := mathRand.Intn(5) + 5
	lenAfter := len(p) + lenBefore%16
	beforeBytes := make([]byte, lenBefore)
	afterBytes := make([]byte, lenAfter)
	_, err := rand.Read(beforeBytes)
	if err != nil {
		return nil, err
	}
	_, err = rand.Read(afterBytes)
	if err != nil {
		return nil, err
	}
	return append(append(beforeBytes, p...), afterBytes...), nil
}

func GuessAESMode(e EncryptedText) AESMode {
	if smellsOfECB(e.ciphertext) {
		return ECB
	}
	return CBC
}

func inferBlocksize(f EncryptionFn) (int, error) {
	i := 2
	initial, err := f([]byte("A"))
	if err != nil {
		return 0, err
	}
	for true {
		next, err := f(bytes.Repeat([]byte("A"), i))
		if err != nil {
			return 0, err
		}
		diff := len(next.ciphertext) - len(initial.ciphertext)
		if diff > 0 {
			return diff, nil
		}
		i++
	}
	return 0, nil
}

func ChunkForAES(b []byte) [][]byte {
	return chunk(b, aes.BlockSize)
}

func AByteBlock() []byte {
	return bytes.Repeat(ByteA, aes.BlockSize)
}

type Encryptor struct {
	mode      AESMode
	key       []byte
	plaintext []byte
}

func NewEncryptor(plain []byte, mode AESMode) (Encryptor, error) {
	b, err := addRandomBytes(plain)
	if err != nil {
		return Encryptor{}, err
	}
	key, err := generateRandomBlock()
	if err != nil {
		return Encryptor{}, err
	}
	return Encryptor{mode: mode, plaintext: b, key: key}, nil
}

func (o Encryptor) getPlaintext() PlainText {
	return PlainText{plaintext: o.plaintext, key: o.key}
}

func (o Encryptor) Encrypt() (EncryptedText, error) {
	switch o.mode {
	case ECB:
		return Encrypt(ECB, o.getPlaintext())
	case CBC:
		return Encrypt(CBC, o.getPlaintext())
	}
	return EncryptedText{}, fmt.Errorf("Mode %d unknown", o.mode)
}
