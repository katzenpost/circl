package internal

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/sha3"
)

func hexHash(in []byte) string {
	h := sha3.Sum256(in)
	return hex.EncodeToString(h[:8])
}

func TestEncryptThenDecrypt(t *testing.T) {
	var seed [32]byte
	var coin [SeedSize]byte

	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
		coin[i] = byte(i)
	}

	for i := 0; i < 100; i++ {
		seed[0] = byte(i)
		pk, sk := NewKeyFromSeed(seed[:])

		for j := 0; j < 100; j++ {
			var msg, msg2 [PlaintextSize]byte
			var ct [CiphertextSize]byte

			_, _ = rand.Read(msg[:])
			_, _ = rand.Read(coin[:])

			pk.EncryptTo(msg[:], coin[:], ct[:])
			sk.DecryptTo(ct[:], msg2[:])

			if msg != msg2 {
				t.Fatalf("%v %v %v", ct, msg, msg2)
			}
		}
	}
}