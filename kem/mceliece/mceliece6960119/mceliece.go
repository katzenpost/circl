// Code generated from mceliece.templ.go. DO NOT EDIT.

// Package mceliece6960119 implements the IND-CCA2 secure key encapsulation mechanism
// mceliece6960119 as submitted to round 4 of the NIST PQC competition and
// described in
//
// https://classic.mceliece.org/nist/mceliece-20201010.pdf
//
// The following code is translated from the C reference implementation, and
// from a Rust implementation by Bernhard Berg, Lukas Prokop, Daniel Kales
// where direct translation from C is not applicable.
//
// https://github.com/Colfenor/classic-mceliece-rust
package mceliece6960119

import (
	"bytes"
	cryptoRand "crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/pem"

	"github.com/katzenpost/circl/internal/nist"
	"github.com/katzenpost/circl/internal/sha3"
	"github.com/katzenpost/circl/kem/mceliece/internal"
	"github.com/katzenpost/circl/math/gf2e13"
)

const (
	sysT                  = 119 // F(y) is 64 degree
	gfBits                = gf2e13.Bits
	gfMask                = gf2e13.Mask
	unusedBits            = 16 - gfBits
	sysN                  = 6960
	condBytes             = (1 << (gfBits - 4)) * (2*gfBits - 1)
	irrBytes              = sysT * 2
	pkNRows               = sysT * gfBits
	pkNCols               = sysN - pkNRows
	pkRowBytes            = (pkNCols + 7) / 8
	syndBytes             = (pkNRows + 7) / 8
	PublicKeySize         = 1047319
	PrivateKeySize        = 13948
	CiphertextSize        = 194
	SharedKeySize         = 32
	seedSize              = 32
	encapsulationSeedSize = 48
)

type PublicKey struct {
	pk [PublicKeySize]byte
}

type PrivateKey struct {
	sk [PrivateKeySize]byte
}

type (
	gf       = gf2e13.Elt
	randFunc = func(pool []byte) error
)

// KEM Keypair generation.
//
// The structure of the secret key is given by the following segments:
// (32 bytes seed, 8 bytes pivots, IRR_BYTES bytes, COND_BYTES bytes, SYS_N/8 bytes).
// The structure of the public key is simple: a matrix of PK_NROWS times PK_ROW_BYTES bytes.
//
// `entropy` corresponds to the l-bit input seed in SeededKeyGen from the specification.
// The keypair is deterministically generated from `entropy`.
// If the generated keypair is invalid, a new seed will be generated by hashing `entropy` to try again.
func deriveKeyPair(entropy []byte) (*PublicKey, *PrivateKey) {
	const (
		irrPolys  = sysN/8 + (1<<gfBits)*4
		seedIndex = sysN/8 + (1<<gfBits)*4 + sysT*2
		permIndex = sysN / 8
		sBase     = 32 + 8 + irrBytes + condBytes
	)

	var (
		pk [PublicKeySize]byte
		sk [PrivateKeySize]byte
	)

	seed := [33]byte{64}
	r := [sysN/8 + (1<<gfBits)*4 + sysT*2 + 32]byte{}

	f := [sysT]gf{}
	irr := [sysT]gf{}
	perm := [1 << gfBits]uint32{}
	pi := [1 << gfBits]int16{}
	pivots := uint64(0xFFFFFFFF)

	copy(seed[1:], entropy[:])

	for {
		// expanding and updating the seed
		err := shake256(r[:], seed[0:33])
		if err != nil {
			panic(err)
		}

		copy(sk[:32], seed[1:])
		copy(seed[1:], r[len(r)-32:])

		temp := r[irrPolys:seedIndex]
		for i := 0; i < sysT; i++ {
			f[i] = loadGf(temp)
			temp = temp[2:]
		}

		if !minimalPolynomial(&irr, &f) {
			continue
		}

		temp = sk[40 : 40+irrBytes]
		for i := 0; i < sysT; i++ {
			storeGf(temp, irr[i])
			temp = temp[2:]
		}

		// generating permutation
		temp = r[permIndex:irrPolys]
		for i := 0; i < 1<<gfBits; i++ {
			perm[i] = load4(temp)
			temp = temp[4:]
		}

		if !pkGen(&pk, sk[40:40+irrBytes], &perm, &pi, &pivots) {
			continue
		}

		internal.ControlBitsFromPermutation(sk[32+8+irrBytes:], pi[:], gfBits, 1<<gfBits)
		copy(sk[sBase:sBase+sysN/8], r[0:sysN/8])
		store8(sk[32:40], pivots)
		return &PublicKey{pk: pk}, &PrivateKey{sk: sk}
	}
}

// Encryption routine.
// Takes a public key `pk` to compute error vector `e` and syndrome `s`.
func encrypt(s *[CiphertextSize]byte, pk *[PublicKeySize]byte, e *[sysN / 8]byte, rand randFunc) error {
	err := genE(e, rand)
	if err != nil {
		return err
	}
	syndrome(s, pk, e)
	return nil
}

// KEM Encapsulation.
//
// Given a public key `pk`, sample a shared key.
// This shared key is returned through parameter `key` whereas
// the ciphertext (meant to be used for decapsulation) is returned as `c`.
func kemEncapsulate(c *[CiphertextSize]byte, key *[SharedKeySize]byte, pk *[PublicKeySize]byte, rand randFunc) error {
	e := [sysN / 8]byte{}
	oneEC := [1 + sysN/8 + syndBytes]byte{1}

	paddingOk := checkPkPadding(pk)

	err := encrypt(c, pk, &e, rand)
	if err != nil {
		return err
	}
	copy(oneEC[1:1+sysN/8], e[:sysN/8])
	copy(oneEC[1+sysN/8:1+sysN/8+syndBytes], c[:syndBytes])
	err = shake256(key[0:32], oneEC[:])
	if err != nil {
		return err
	}

	mask := paddingOk ^ 0xFF
	for i := 0; i < syndBytes; i++ {
		c[i] &= mask
	}
	for i := 0; i < 32; i++ {
		key[i] &= mask
	}

	if paddingOk == 0 {
		return nil
	}
	return fmt.Errorf("public key padding error %d", paddingOk)
}

// KEM Decapsulation.
//
// Given a secret key `sk` and a ciphertext `c`,
// determine the shared text `key` negotiated by both parties.
func kemDecapsulate(key *[SharedKeySize]byte, c *[CiphertextSize]byte, sk *[PrivateKeySize]byte) error {
	e := [sysN / 8]byte{}
	preimage := [1 + sysN/8 + syndBytes]byte{}
	s := sk[40+irrBytes+condBytes:]

	paddingOk := checkCPadding(c)

	retDecrypt := decrypt((*[sysN / 8]byte)(e[:sysN/8]), sk[40:], (*[syndBytes]byte)(c[:syndBytes]))
	m := retDecrypt
	m -= 1
	m >>= 8

	preimage[0] = byte(m & 1)
	for i := 0; i < sysN/8; i++ {
		preimage[1+i] = (byte(^m) & s[i]) | (byte(m) & e[i])
	}

	copy(preimage[1+sysN/8:][:syndBytes], c[0:syndBytes])
	err := shake256(key[0:32], preimage[:])
	if err != nil {
		return err
	}

	// clear outputs (set to all 1's) if padding bits are not all zero
	mask := paddingOk
	for i := 0; i < 32; i++ {
		key[i] |= mask
	}

	if paddingOk == 0 {
		return nil
	}
	return fmt.Errorf("public key padding error %d", paddingOk)
}

// Generates `e`, a random error vector of weight `t`.
// If generation of pseudo-random numbers fails, an error is returned
func genE(e *[sysN / 8]byte, rand randFunc) error {
	ind := [sysT]uint16{}
	val := [sysT]byte{}
	for {
		buf := make([]byte, sysT*4)
		err := rand(buf)
		if err != nil {
			return err
		}

		nums := [sysT * 2]uint16{}
		for i := 0; i < sysT*2; i++ {
			nums[i] = loadGf(buf[:])
			buf = buf[2:]
		}

		count := 0
		for i := 0; i < sysT*2 && count < sysT; i++ {
			if nums[i] < sysN {
				ind[count] = nums[i]
				count++
			}
		}
		if count < sysT {
			continue
		}

		eq := false
		for i := 1; i < sysT; i++ {
			for j := 0; j < i; j++ {
				if ind[i] == ind[j] {
					eq = true
				}
			}
		}

		if !eq {
			break
		}
	}

	for j := 0; j < sysT; j++ {
		val[j] = 1 << (ind[j] & 7)
	}

	for i := uint16(0); i < sysN/8; i++ {
		e[i] = 0

		for j := 0; j < sysT; j++ {
			mask := sameMask(i, ind[j]>>3)
			e[i] |= val[j] & mask
		}
	}
	return nil
}

// Takes two 16-bit integers and determines whether they are equal
// Return byte with all bit set if equal, 0 otherwise
func sameMask(x uint16, y uint16) byte {
	mask := uint32(x ^ y)
	mask -= 1
	mask >>= 31
	mask = -mask

	return byte(mask & 0xFF)
}

// Given condition bits `c`, returns the support `s`.
func supportGen(s *[sysN]gf, c *[condBytes]byte) {
	L := [gfBits][(1 << gfBits) / 8]byte{}
	for i := 0; i < (1 << gfBits); i++ {
		a := bitRev(gf(i))
		for j := 0; j < gfBits; j++ {
			L[j][i/8] |= byte(((a >> j) & 1) << (i % 8))
		}
	}
	for j := 0; j < gfBits; j++ {
		applyBenes(&L[j], c)
	}
	for i := 0; i < sysN; i++ {
		s[i] = 0
		for j := gfBits - 1; j >= 0; j-- {
			s[i] <<= 1
			s[i] |= uint16(L[j][i/8]>>(i%8)) & 1
		}
	}
}

// Given Goppa polynomial `f`, support `l`, and received word `r`
// compute `out`, the syndrome of length 2t
func synd(out *[sysT * 2]gf, f *[sysT + 1]gf, L *[sysN]gf, r *[sysN / 8]byte) {
	for j := 0; j < 2*sysT; j++ {
		out[j] = 0
	}

	for i := 0; i < sysN; i++ {
		c := uint16(r[i/8]>>(i%8)) & 1
		e := eval(f, L[i])
		eInv := gf2e13.Inv(gf2e13.Mul(e, e))
		for j := 0; j < 2*sysT; j++ {
			out[j] = gf2e13.Add(out[j], gf2e13.Mul(eInv, c))
			eInv = gf2e13.Mul(eInv, L[i])
		}
	}
}

func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}

// The Berlekamp-Massey algorithm. <http://crypto.stanford.edu/~mironov/cs359/massey.pdf>
// Uses `s` as input (sequence of field elements)
// and `out` as output (minimal polynomial of `s`)
func bm(out *[sysT + 1]gf, s *[2 * sysT]gf) {
	var L, mle, mne uint16
	T := [sysT + 1]gf{}
	C := [sysT + 1]gf{}
	B := [sysT + 1]gf{}
	var b, d, f gf
	b = 1
	B[1] = 1
	C[0] = 1
	for N := 0; N < 2*sysT; N++ {
		d = 0
		for i := 0; i <= min(N, sysT); i++ {
			d ^= gf2e13.Mul(C[i], s[N-i])
		}
		mne = d
		mne -= 1
		mne >>= 15
		mne -= 1
		mle = uint16(N)
		mle -= 2 * L
		mle >>= 15
		mle -= 1
		mle &= mne
		for i := 0; i <= sysT; i++ {
			T[i] = C[i]
		}
		f = gf2e13.Div(d, b)
		for i := 0; i <= sysT; i++ {
			C[i] ^= gf2e13.Mul(f, B[i]) & mne
		}
		L = (L & ^mle) | ((uint16(N) + 1 - L) & mle)

		for i := 0; i <= sysT; i++ {
			B[i] = (B[i] & ^mle) | (T[i] & mle)
		}

		b = (b & ^mle) | (d & mle)

		for i := sysT; i >= 1; i-- {
			B[i] = B[i-1]
		}
		B[0] = 0
	}

	for i := 0; i <= sysT; i++ {
		out[i] = C[sysT-i]
	}
}

// Niederreiter decryption with the Berlekamp decoder.
//
// It takes as input the secret key `sk` and a ciphertext `c`.
// It returns an error vector in `e` and the return value indicates success (0) or failure (1)
func decrypt(e *[sysN / 8]byte, sk []byte, c *[syndBytes]byte) uint16 {
	var check uint16
	w := 0
	r := [sysN / 8]byte{}

	g := [sysT + 1]gf{}
	L := [sysN]gf{}

	s := [sysT * 2]gf{}
	sCmp := [sysT * 2]gf{}
	locator := [sysT + 1]gf{}
	images := [sysN]gf{}

	copy(r[:syndBytes], c[:syndBytes])
	for i := 0; i < sysT; i++ {
		g[i] = loadGf(sk)
		sk = sk[2:]
	}
	g[sysT] = 1

	supportGen(&L, (*[condBytes]byte)(sk[:condBytes]))

	synd(&s, &g, &L, &r)
	bm(&locator, &s)
	root(&images, &locator, &L)

	for i := 0; i < sysN/8; i++ {
		e[i] = 0
	}
	for i := 0; i < sysN; i++ {
		t := isZeroMask(images[i]) & 1

		e[i/8] |= byte(t << (i % 8))
		w += int(t)
	}

	synd(&sCmp, &g, &L, e)
	check = uint16(w) ^ sysT
	for i := 0; i < sysT*2; i++ {
		check |= s[i] ^ sCmp[i]
	}

	check -= 1
	check >>= 15

	return check ^ 1
}

// check if element is 0, returns a mask with all bits set if so, and 0 otherwise
func isZeroMask(element gf) uint16 {
	t := uint32(element) - 1
	t >>= 19
	return uint16(t)
}

// calculate the minimal polynomial of f and store it in out
func minimalPolynomial(out *[sysT]gf, f *[sysT]gf) bool {
	mat := [sysT + 1][sysT]gf{}
	mat[0][0] = 1
	for i := 1; i < sysT; i++ {
		mat[0][i] = 0
	}

	for i := 0; i < sysT; i++ {
		mat[1][i] = f[i]
	}

	for i := 2; i <= sysT; i++ {
		polyMul(&mat[i], &mat[i-1], f)
	}

	for j := 0; j < sysT; j++ {
		for k := j + 1; k < sysT; k++ {
			mask := isZeroMask(mat[j][j])
			// if mat[j][j] is not zero, add mat[c..sysT+1][k] to mat[c][j]
			// do nothing otherwise
			for c := j; c <= sysT; c++ {
				mat[c][j] ^= mat[c][k] & mask
			}
		}

		if mat[j][j] == 0 {
			return false
		}

		inv := gf2e13.Inv(mat[j][j])
		for c := 0; c <= sysT; c++ {
			mat[c][j] = gf2e13.Mul(mat[c][j], inv)
		}

		for k := 0; k < sysT; k++ {
			if k != j {
				t := mat[j][k]
				for c := 0; c <= sysT; c++ {
					mat[c][k] ^= gf2e13.Mul(mat[c][j], t)
				}
			}
		}
	}

	for i := 0; i < sysT; i++ {
		out[i] = mat[sysT][i]
	}

	return true
}

// calculate the product of a and b in Fq^t
func polyMul(out *[sysT]gf, a *[sysT]gf, b *[sysT]gf) {
	product := [sysT*2 - 1]gf{}
	for i := 0; i < sysT; i++ {
		for j := 0; j < sysT; j++ {
			product[i+j] ^= gf2e13.Mul(a[i], b[j])
		}
	}

	for i := (sysT - 1) * 2; i >= sysT; i-- {
		// polynomial reduction

		product[i-sysT+8] ^= product[i]
		product[i-sysT+0] ^= product[i]

	}

	for i := 0; i < sysT; i++ {
		out[i] = product[i]
	}
}

// Compute transposition of `in` and store it in `out`
func transpose64x64(out, in *[64]uint64) {
	masks := [6][2]uint64{
		{0x5555555555555555, 0xAAAAAAAAAAAAAAAA},
		{0x3333333333333333, 0xCCCCCCCCCCCCCCCC},
		{0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0},
		{0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00},
		{0x0000FFFF0000FFFF, 0xFFFF0000FFFF0000},
		{0x00000000FFFFFFFF, 0xFFFFFFFF00000000},
	}
	copy(out[:], in[:])

	for d := 5; d >= 0; d-- {
		s := 1 << d
		for i := 0; i < 64; i += s * 2 {
			for j := i; j < i+s; j++ {
				x := (out[j] & masks[d][0]) | ((out[j+s] & masks[d][0]) << s)
				y := ((out[j] & masks[d][1]) >> s) | (out[j+s] & masks[d][1])

				out[j+0] = x
				out[j+s] = y
			}
		}
	}
}

// given polynomial `f`, evaluate `f` at `a`
func eval(f *[sysT + 1]gf, a gf) gf {
	r := f[sysT]
	for i := sysT - 1; i >= 0; i-- {
		r = gf2e13.Mul(r, a)
		r = gf2e13.Add(r, f[i])
	}
	return r
}

// Given polynomial `f` and a list of field elements `l`,
// return the roots `out` satisfying `[ f(a) for a in L ]`
func root(out *[sysN]gf, f *[sysT + 1]gf, l *[sysN]gf) {
	for i := 0; i < sysN; i++ {
		out[i] = eval(f, l[i])
	}
}

// performs SHAKE-256 on `input` and store the hash in `output`
func shake256(output []byte, input []byte) error {
	shake := sha3.NewShake256()
	_, err := shake.Write(input)
	if err != nil {
		return err
	}
	_, err = shake.Read(output)
	if err != nil {
		return err
	}
	return nil
}

// store field element `a` in the first 2 bytes of `dest`
func storeGf(dest []byte, a gf) {
	dest[0] = byte(a & 0xFF)
	dest[1] = byte(a >> 8)
}

// load a field element from the first 2 bytes of `src`
func loadGf(src []byte) gf {
	a := uint16(src[1])
	a <<= 8
	a |= uint16(src[0])
	return a & gfMask
}

// load a 32-bit little endian integer from `in`
func load4(in []byte) uint32 {
	ret := uint32(in[3])
	for i := 2; i >= 0; i-- {
		ret <<= 8
		ret |= uint32(in[i])
	}
	return ret
}

// store a 64-bit integer to `out` in little endian
func store8(out []byte, in uint64) {
	out[0] = byte((in >> 0x00) & 0xFF)
	out[1] = byte((in >> 0x08) & 0xFF)
	out[2] = byte((in >> 0x10) & 0xFF)
	out[3] = byte((in >> 0x18) & 0xFF)
	out[4] = byte((in >> 0x20) & 0xFF)
	out[5] = byte((in >> 0x28) & 0xFF)
	out[6] = byte((in >> 0x30) & 0xFF)
	out[7] = byte((in >> 0x38) & 0xFF)
}

// load a 64-bit little endian integer from `in`
func load8(in []byte) uint64 {
	ret := uint64(in[7])
	for i := 6; i >= 0; i-- {
		ret <<= 8
		ret |= uint64(in[i])
	}
	return ret
}

// reverse the bits in the field element `a`
func bitRev(a gf) gf {
	a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8)
	a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4)
	a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2)
	a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1)

	return a >> unusedBits
}

type scheme struct{}

var sch kem.Scheme = &scheme{}

// Scheme returns a KEM interface.
func Scheme() kem.Scheme { return sch }

func (*scheme) Name() string               { return "mceliece6960119" }
func (*scheme) PublicKeySize() int         { return PublicKeySize }
func (*scheme) PrivateKeySize() int        { return PrivateKeySize }
func (*scheme) SeedSize() int              { return seedSize }
func (*scheme) SharedKeySize() int         { return SharedKeySize }
func (*scheme) CiphertextSize() int        { return CiphertextSize }
func (*scheme) EncapsulationSeedSize() int { return encapsulationSeedSize }

func (sk *PrivateKey) Scheme() kem.Scheme { return sch }
func (pk *PublicKey) Scheme() kem.Scheme  { return sch }

func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	var ret [PrivateKeySize]byte
	copy(ret[:], sk.sk[:])
	return ret[:], nil
}

// MarshalCompressedBinary returns a 32-byte seed that can be used to regenerate
// the key pair when passed to DeriveKeyPair
func (sk *PrivateKey) MarshalCompressedBinary() []byte {
	seed := [32]byte{}
	copy(seed[:], sk.sk[:32])
	return seed[:]
}

func (sk *PrivateKey) Equal(other kem.PrivateKey) bool {
	oth, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return bytes.Equal(sk.sk[:], oth.sk[:])
}

func (pk *PublicKey) Equal(other kem.PublicKey) bool {
	oth, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(pk.pk[:], oth.pk[:])
}

func (sk *PrivateKey) Public() kem.PublicKey {
	pk, _ := sch.DeriveKeyPair(sk.MarshalCompressedBinary())
	return pk
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	var ret [PublicKeySize]byte
	copy(ret[:], pk.pk[:])
	return ret[:], nil
}

func (pk *PublicKey) MarshalText() (text []byte, err error) {
	return pem.ToPublicPEMBytes(pk), nil
}

func (pk *PublicKey) UnmarshalText(text []byte) error {
	blob, err := pem.FromPublicPEMToBytes(text, pk.Scheme())
	if err != nil {
		return err
	}
	pubkey, err := pk.Scheme().UnmarshalBinaryPublicKey(blob)
	if err != nil {
		return err
	}
	newpk, ok := pubkey.(*PublicKey)
	if !ok {
		return errors.New("public key type assertion failed")
	}
	*pk = *newpk
	return nil
}

func (*scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	seed := [32]byte{}
	_, err := io.ReadFull(cryptoRand.Reader, seed[:])
	if err != nil {
		return nil, nil, err
	}
	pk, sk := deriveKeyPair(seed[:])
	return pk, sk, nil
}

func (*scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != seedSize {
		panic("seed must be of length EncapsulationSeedSize")
	}
	return deriveKeyPair(seed)
}

func encapsulate(pk kem.PublicKey, rand randFunc) (ct, ss []byte, err error) {
	ppk, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}

	ciphertext := [CiphertextSize]byte{}
	sharedSecret := [SharedKeySize]byte{}
	err = kemEncapsulate(&ciphertext, &sharedSecret, &ppk.pk, rand)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext[:], sharedSecret[:], nil
}

func (*scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	return encapsulate(pk, func(pool []byte) error {
		_, err2 := io.ReadFull(cryptoRand.Reader, pool)
		return err2
	})
}

func (*scheme) EncapsulateDeterministically(pk kem.PublicKey, seed []byte) (ct, ss []byte, err error) {
	// This follow test standards
	if len(seed) != encapsulationSeedSize {
		return nil, nil, kem.ErrSeedSize
	}

	entropy := [48]byte{}
	waste := [32]byte{}
	copy(entropy[:], seed)
	dRng := nist.NewDRBG(&entropy)
	dRng.Fill(waste[:])

	return encapsulate(pk, func(pool []byte) error {
		dRng.Fill(pool)
		return nil
	})
}

func (*scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	ssk, ok := sk.(*PrivateKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}

	if len(ct) != CiphertextSize {
		return nil, kem.ErrCiphertextSize
	}
	ss := [SharedKeySize]byte{}
	err := kemDecapsulate(&ss, (*[CiphertextSize]byte)(ct), &ssk.sk)
	if err != nil {
		return nil, err
	}
	return ss[:], nil
}

func (*scheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	if len(buf) != PublicKeySize {
		return nil, kem.ErrPubKeySize
	}
	pk := [PublicKeySize]byte{}
	copy(pk[:], buf)
	return &PublicKey{pk: pk}, nil
}

func (*scheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	if len(buf) != PrivateKeySize {
		return nil, kem.ErrPrivKeySize
	}
	sk := [PrivateKeySize]byte{}
	copy(sk[:], buf)
	return &PrivateKey{sk: sk}, nil
}
