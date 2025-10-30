package kem

import (
	hpqcKem "github.com/katzenpost/hpqc/kem"
)

// hpqcAdapter wraps an hpqc/kem.Scheme to implement circl/kem.Scheme.
// This allows newer hpqc-based KEM schemes (like Kyber, McEliece) to be used
// with code that expects the circl/kem interface (like HPKE).
type hpqcAdapter struct {
	scheme hpqcKem.Scheme
}

// FromHPQC creates a circl/kem.Scheme from an hpqc/kem.Scheme.
func FromHPQC(scheme hpqcKem.Scheme) Scheme {
	return &hpqcAdapter{scheme: scheme}
}

func (a *hpqcAdapter) Name() string               { return a.scheme.Name() }
func (a *hpqcAdapter) PublicKeySize() int         { return a.scheme.PublicKeySize() }
func (a *hpqcAdapter) PrivateKeySize() int        { return a.scheme.PrivateKeySize() }
func (a *hpqcAdapter) SeedSize() int              { return a.scheme.SeedSize() }
func (a *hpqcAdapter) SharedKeySize() int         { return a.scheme.SharedKeySize() }
func (a *hpqcAdapter) CiphertextSize() int        { return a.scheme.CiphertextSize() }
func (a *hpqcAdapter) EncapsulationSeedSize() int { return a.scheme.EncapsulationSeedSize() }

func (a *hpqcAdapter) GenerateKeyPair() (PublicKey, PrivateKey, error) {
	pk, sk, err := a.scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return &hpqcPublicKey{pk: pk, adapter: a}, &hpqcPrivateKey{sk: sk, adapter: a}, nil
}

func (a *hpqcAdapter) DeriveKeyPair(seed []byte) (PublicKey, PrivateKey) {
	pk, sk := a.scheme.DeriveKeyPair(seed)
	return &hpqcPublicKey{pk: pk, adapter: a}, &hpqcPrivateKey{sk: sk, adapter: a}
}

func (a *hpqcAdapter) Encapsulate(pk PublicKey) (ct, ss []byte, err error) {
	hpk, ok := pk.(*hpqcPublicKey)
	if !ok {
		return nil, nil, ErrTypeMismatch
	}
	return a.scheme.Encapsulate(hpk.pk)
}

func (a *hpqcAdapter) EncapsulateDeterministically(pk PublicKey, seed []byte) (ct, ss []byte, err error) {
	hpk, ok := pk.(*hpqcPublicKey)
	if !ok {
		return nil, nil, ErrTypeMismatch
	}
	return a.scheme.EncapsulateDeterministically(hpk.pk, seed)
}

func (a *hpqcAdapter) Decapsulate(sk PrivateKey, ct []byte) ([]byte, error) {
	hsk, ok := sk.(*hpqcPrivateKey)
	if !ok {
		return nil, ErrTypeMismatch
	}
	return a.scheme.Decapsulate(hsk.sk, ct)
}

func (a *hpqcAdapter) UnmarshalBinaryPublicKey(buf []byte) (PublicKey, error) {
	pk, err := a.scheme.UnmarshalBinaryPublicKey(buf)
	if err != nil {
		return nil, err
	}
	return &hpqcPublicKey{pk: pk, adapter: a}, nil
}

func (a *hpqcAdapter) UnmarshalBinaryPrivateKey(buf []byte) (PrivateKey, error) {
	sk, err := a.scheme.UnmarshalBinaryPrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return &hpqcPrivateKey{sk: sk, adapter: a}, nil
}

// hpqcPublicKey wraps an hpqc/kem.PublicKey to implement circl/kem.PublicKey
type hpqcPublicKey struct {
	pk      hpqcKem.PublicKey
	adapter *hpqcAdapter
}

func (k *hpqcPublicKey) Scheme() Scheme              { return k.adapter }
func (k *hpqcPublicKey) MarshalBinary() ([]byte, error) { return k.pk.MarshalBinary() }

func (k *hpqcPublicKey) Equal(other PublicKey) bool {
	oth, ok := other.(*hpqcPublicKey)
	if !ok {
		return false
	}
	return k.pk.Equal(oth.pk)
}

// hpqcPrivateKey wraps an hpqc/kem.PrivateKey to implement circl/kem.PrivateKey
type hpqcPrivateKey struct {
	sk      hpqcKem.PrivateKey
	adapter *hpqcAdapter
}

func (k *hpqcPrivateKey) Scheme() Scheme               { return k.adapter }
func (k *hpqcPrivateKey) MarshalBinary() ([]byte, error) { return k.sk.MarshalBinary() }
func (k *hpqcPrivateKey) Public() PublicKey {
	return &hpqcPublicKey{pk: k.sk.Public(), adapter: k.adapter}
}

func (k *hpqcPrivateKey) Equal(other PrivateKey) bool {
	oth, ok := other.(*hpqcPrivateKey)
	if !ok {
		return false
	}
	return k.sk.Equal(oth.sk)
}
