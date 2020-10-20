package pals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	mathRand "math/rand"

	"github.com/nadavoosh/go_crypto_pals/pkg/utils"
)

// modes for encryption
const (
	ECB AESMode = 0
	CBC AESMode = 1
)

type AESMode int

type AES interface {
	Encrypt(k Key) (Ciphertext, error)
	Decrypt(k Key) (Plaintext, error)
}

type Ciphertext []byte
type Plaintext []byte
type IV []byte
type Key []byte

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

func GuessAESMode(e Ciphertext) AESMode {
	if SmellsOfECB(e) {
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
		diff := len(next) - len(initial)
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
	return bytes.Repeat(utils.ByteA, aes.BlockSize)
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
	Key, err := utils.GenerateRandomBlock()
	if err != nil {
		return Encryptor{}, err
	}
	return Encryptor{mode: mode, Plaintext: b, Key: Key}, nil
}

func (o Encryptor) Encrypt() (Ciphertext, error) {
	switch o.mode {
	case ECB:
		return AES_ECB{Plaintext: o.Plaintext}.Encrypt(o.Key)
	case CBC:
		d := AES_CBC{Plaintext: o.Plaintext}
		return d.Encrypt(o.Key)
	}
	return nil, fmt.Errorf("Mode %v is unknown", o.mode)
}
