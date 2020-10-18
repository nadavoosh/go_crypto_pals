package pals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	mathRand "math/rand"
)

type AESMode int

// modes for encryption
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
		if d.IV == nil {
			IV, err := generateRandomBlock()
			if err != nil {
				return EncryptedText{}, err
			}
			d.IV = IV
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
		return DecryptECB(e)
	case CBC:
		if e.IV == nil {
			IV, err := generateRandomBlock()
			if err != nil {
				return PlainText{}, err
			}
			e.IV = IV
		}
		return DecryptCBC(e)
	case CTC:
		return decryptCTC(e)
	case MT:
		return decryptMT(e)
	default:
		return PlainText{}, fmt.Errorf("Mode %d unknown", mode)
	}
}

func encryptSingleBlock(cipher cipher.Block, Plaintext []byte) []byte {
	dst := make([]byte, aes.BlockSize)
	cipher.Encrypt(dst, Plaintext)
	return dst
}

func decryptSingleBlock(cipher cipher.Block, Ciphertext []byte) []byte {
	dst := make([]byte, aes.BlockSize)
	cipher.Decrypt(dst, Ciphertext)
	return dst
}

func generateRandomBlock() ([]byte, error) {
	Key := make([]byte, aes.BlockSize)
	_, err := rand.Read(Key)
	return Key, err
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
	if SmellsOfECB(e.Ciphertext) {
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
		diff := len(next.Ciphertext) - len(initial.Ciphertext)
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
	Key       []byte
	Plaintext []byte
}

func NewEncryptor(plain []byte, mode AESMode) (Encryptor, error) {
	b, err := addRandomBytes(plain)
	if err != nil {
		return Encryptor{}, err
	}
	Key, err := generateRandomBlock()
	if err != nil {
		return Encryptor{}, err
	}
	return Encryptor{mode: mode, Plaintext: b, Key: Key}, nil
}

func (o Encryptor) getPlaintext() PlainText {
	return PlainText{Plaintext: o.Plaintext, CryptoMaterial: CryptoMaterial{Key: o.Key}}
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