package pals

import (
	"crypto/rand"
	mathRand "math/rand"
	"time"
)

var FixedKey = GenerateKey()
var FixedBytes = GenerateRandomBytes()

// GenerateKey returns a random Key
func GenerateKey() []byte {
	k, _ := generateRandomBlock()
	return k
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
