package utils

import "crypto/sha256"

// Sha256d calculates hash(hash(b)) and returns the resulting bytes.
func Sha256d(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

// GetBitcoinHash calculates the Bitcoin hash of the given bytes.
// The Bitcoin hash is the double SHA-256 hash of the given bytes
// which is then reversed.
// For transactions the entire transaction bytes are hashed; for blocks
// only the header (80 bytes) is hashed.
func GetBitcoinHash(b []byte) []byte {
	return ReverseSlice(Sha256d(b))
}
