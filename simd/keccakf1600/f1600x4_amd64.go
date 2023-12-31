package keccakf1600

import "github.com/katzenpost/circl/internal/sha3"

func permuteSIMDx4(state []uint64) { f1600x4AVX2(&state[0], &sha3.RC) }

func permuteSIMDx2(state []uint64) { permuteScalarX2(state) }
