package ed448_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/ed448"
)

func TestWrongPublicKey(t *testing.T) {
	wrongPublicKeys := [...][ed448.Size]byte{
		{ // y = p
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
		{ // y > p
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
		{ // x^2 = u/v = (y^2-1)/(dy^2-1) is not a quadratic residue
			0xa4, 0x8b, 0xae, 0x31, 0x1b, 0x3a, 0xe5, 0x62,
			0x3d, 0x6f, 0x2d, 0xbe, 0x8b, 0xb4, 0xd3, 0x21,
			0x0f, 0x04, 0x0a, 0x7e, 0xf2, 0x25, 0x87, 0xc3,
			0xc0, 0x1e, 0xe1, 0xf4, 0x6d, 0xc7, 0x28, 0x8f,
			0x8b, 0xb9, 0x9f, 0x3d, 0x02, 0xb0, 0xc0, 0xa8,
			0xe7, 0xe3, 0x4f, 0xb2, 0x82, 0x64, 0x98, 0x4a,
			0x84, 0x73, 0xd7, 0x57, 0x6a, 0x39, 0x90, 0xa3,
		},
		{ // y = 1 and x^2 = u/v = 0, and the sign of X is 1
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
		},
		{ // y = -1 and x^2 = u/v = 0, and the sign of X is 1
			0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80,
		},
	}
	sig := make([]byte, 2*ed448.Size)
	for _, public := range wrongPublicKeys {
		got := ed448.Verify(public[:], []byte(""), []byte(""), sig)
		want := false
		if got != want {
			test.ReportError(t, got, want, public)
		}
	}
}

func BenchmarkEd448(b *testing.B) {
	msg := make([]byte, 128)
	ctx := make([]byte, 128)
	_, _ = rand.Read(msg)
	_, _ = rand.Read(ctx)

	key, _ := ed448.GenerateKey(rand.Reader)
	pub := key.GetPublic()
	sig := ed448.Sign(key, msg, ctx)

	b.Run("keygen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ed448.GenerateKey(rand.Reader)
		}
	})
	b.Run("sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ed448.Sign(key, msg, ctx)
		}
	})
	b.Run("verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ed448.Verify(pub, msg, ctx, sig)
		}
	})
}

func Example_ed448() {
	// import "github.com/cloudflare/circl/sign/ed448"

	// Generating Alice's key pair
	keys, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		panic("error on generating keys")
	}

	// Alice signs a message.
	message := []byte("A message to be signed")
	context := []byte("This is a context string")
	signature := ed448.Sign(keys, message, context)

	// Anyone can verify the signature using Alice's public key.
	ok := ed448.Verify(keys.GetPublic(), message, context, signature)
	fmt.Println(ok)
	// Output: true
}