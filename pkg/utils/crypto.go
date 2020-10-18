package utils

import (
	"crypto/aes"
	"crypto/rand"
	mathRand "math/rand"
	"time"
)

var FixedKey = GenerateKey()
var FixedBytes = GenerateRandomBytes()

// GenerateKey returns a random Key
func GenerateKey() []byte {
	k, _ := GenerateRandomBlock()
	return k
}

func GenerateRandomBlock() ([]byte, error) {
	Key := make([]byte, aes.BlockSize)
	_, err := rand.Read(Key)
	return Key, err
}

func GenerateRandomBytes() []byte {
	mathRand.Seed(time.Now().UnixNano())
	prepend := make([]byte, mathRand.Intn(1000))
	_, _ = rand.Read(prepend)
	// fmt.Printf("adding %d bytes\n", len(prepend))
	return prepend
}

// ByteA is the "A" byte
var ByteA = []byte("A")
