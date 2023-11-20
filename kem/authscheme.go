package kem

import (
	"github.com/katzenpost/hpqc/primitive/kem"
)

// AuthScheme represents a KEM that supports authenticated key encapsulation.
type AuthScheme interface {
	kem.Scheme
	AuthEncapsulate(pkr kem.PublicKey, sks kem.PrivateKey) (ct, ss []byte, err error)
	AuthEncapsulateDeterministically(pkr kem.PublicKey, sks kem.PrivateKey, seed []byte) (ct, ss []byte, err error)
	AuthDecapsulate(skr kem.PrivateKey, ct []byte, pks kem.PublicKey) ([]byte, error)
}
