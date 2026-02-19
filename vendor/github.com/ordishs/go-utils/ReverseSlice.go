package utils

import "encoding/hex"

// ReverseSliceInPlace reverses the given slice in place.
func ReverseSliceInPlace[T any](a []T) {
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[i], a[j] = a[j], a[i]
	}
}

// Reverse the elements of a 32 byte hash in place
func ReverseHashInPlace(a *[32]byte) {
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[i], a[j] = a[j], a[i]
	}
}

// ReverseSlice reverses the order of the items in the slice.
// A copy of the slice is returned.
func ReverseSlice[T any](a []T) []T {
	tmp := make([]T, len(a))
	copy(tmp, a)

	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		tmp[i], tmp[j] = tmp[j], tmp[i]
	}
	return tmp
}

// Reverse a copy of the 32 byte hash

func ReverseHash(a [32]byte) [32]byte {
	var tmp [32]byte
	copy(tmp[:], a[:])

	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		tmp[i], tmp[j] = tmp[j], tmp[i]
	}

	return tmp
}

// DecodeAndReverseHexString decodes the given hex string and then reverses the bytes.
// This is useful for converting Bitcoin hex strings to byte slices in little endian format.
func DecodeAndReverseHexString(hexStr string) ([]byte, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	ReverseSliceInPlace(b)

	return b, nil
}

func DecodeAndReverseHashString(hexStr string) ([32]byte, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return [32]byte{}, err
	}

	var b32 [32]byte
	copy(b32[:], b)

	return ReverseHash(b32), nil
}

// ReverseAndHexEncodeSlice encodes the given byte slice to a hex string and then reverses the bytes.
func ReverseAndHexEncodeSlice(b []byte) string {
	b = ReverseSlice(b) // This is a copy of the byte slice

	str := hex.EncodeToString(b)

	return str
}

func ReverseAndHexEncodeHash(b32 [32]byte) string {
	b := ReverseSlice(b32[:]) // This is a copy of the byte slice

	str := hex.EncodeToString(b)

	return str
}
