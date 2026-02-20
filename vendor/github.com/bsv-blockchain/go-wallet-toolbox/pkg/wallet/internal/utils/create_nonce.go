package utils

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/wdk"
)

// BytesToUTF8 converts bytes to a UTF-8 string, matching the exact behavior of the
// TypeScript SDK's Utils.toUTF8() function from @bsv/sdk/src/primitives/utils.ts.
//
// This is NOT the same as Go's standard utf8.DecodeRune, which differs in two ways:
//  1. Skip behavior: On invalid continuation bytes, the TS version skips the full
//     expected sequence length (e.g., 2 bytes for a 2-byte lead), while Go only
//     skips 1 byte and reprocesses the rest.
//  2. Overlong encodings: The TS version accepts them (e.g., [0xC0, 0x80] → U+0000),
//     while Go rejects them as invalid.
//
// These differences cause the keyID string to differ between Go and TS, leading to
// different HMAC key derivation and nonce verification failures with TS-based servers.
func BytesToUTF8(data []byte) string {
	var result strings.Builder
	const replacementChar = '\uFFFD'

	i := 0
	for i < len(data) {
		byte1 := data[i]

		// ASCII range (0x00-0x7F)
		if byte1 <= 0x7F {
			result.WriteRune(rune(byte1))
			i++
			continue
		}

		// 2-byte sequence (0xC0-0xDF)
		if byte1 >= 0xC0 && byte1 <= 0xDF {
			if i+1 >= len(data) {
				result.WriteRune(replacementChar)
				i++
				continue
			}
			byte2 := data[i+1]
			if (byte2 & 0xC0) != 0x80 {
				result.WriteRune(replacementChar)
				i += 2 // TS skips both bytes
				continue
			}
			codePoint := (rune(byte1&0x1F) << 6) | rune(byte2&0x3F)
			result.WriteRune(codePoint)
			i += 2
			continue
		}

		// 3-byte sequence (0xE0-0xEF)
		if byte1 >= 0xE0 && byte1 <= 0xEF {
			if i+2 >= len(data) {
				result.WriteRune(replacementChar)
				i++
				continue
			}
			byte2 := data[i+1]
			byte3 := data[i+2]
			if (byte2&0xC0) != 0x80 || (byte3&0xC0) != 0x80 {
				result.WriteRune(replacementChar)
				i += 3 // TS skips all 3 bytes
				continue
			}
			codePoint := (rune(byte1&0x0F) << 12) | (rune(byte2&0x3F) << 6) | rune(byte3&0x3F)
			result.WriteRune(codePoint)
			i += 3
			continue
		}

		// 4-byte sequence (0xF0-0xF7)
		if byte1 >= 0xF0 && byte1 <= 0xF7 {
			if i+3 >= len(data) {
				result.WriteRune(replacementChar)
				i++
				continue
			}
			byte2 := data[i+1]
			byte3 := data[i+2]
			byte4 := data[i+3]
			if (byte2&0xC0) != 0x80 || (byte3&0xC0) != 0x80 || (byte4&0xC0) != 0x80 {
				result.WriteRune(replacementChar)
				i += 4 // TS skips all 4 bytes
				continue
			}
			codePoint := (rune(byte1&0x07) << 18) | (rune(byte2&0x3F) << 12) | (rune(byte3&0x3F) << 6) | rune(byte4&0x3F)
			result.WriteRune(codePoint)
			i += 4
			continue
		}

		// Any other byte (0x80-0xBF, 0xF8-0xFF)
		result.WriteRune(replacementChar)
		i++
	}

	return result.String()
}

const (
	NonceDataSize  = 16
	NonceHMACSize  = 32
	TotalNonceSize = 48
)

// CreateNonce generates a nonce for authentication and replay protection.
// The nonce consists of 16 random bytes followed by a 32-byte HMAC of those bytes,
// using a key associated with the certifier. The resulting 48-byte nonce is then
// base64-encoded to produce a string-safe representation suitable for transmission
// or storage. The structure is:
//
//	[16 random bytes][32 byte HMAC] -> base64-encoded string (returned as string).
//
// This ensures both uniqueness (random bytes) and integrity/authenticity (HMAC).
func CreateNonce(ctx context.Context, wallet sdk.Interface, randomizer wdk.Randomizer, certifier *ec.PublicKey, originator string) (string, error) {
	firstHalf, err := randomizer.Bytes(NonceDataSize)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce data bytes: %w", err)
	}
	keyID := BytesToUTF8(firstHalf)

	createHMACResult, err := wallet.CreateHMAC(ctx, sdk.CreateHMACArgs{
		EncryptionArgs: sdk.EncryptionArgs{
			ProtocolID: sdk.Protocol{
				SecurityLevel: sdk.SecurityLevelEveryAppAndCounterparty,
				Protocol:      "server hmac",
			},
			KeyID: keyID,
			Counterparty: sdk.Counterparty{
				Type:         sdk.CounterpartyTypeOther,
				Counterparty: certifier,
			},
		},
		Data: firstHalf,
	}, originator)
	if err != nil {
		return "", fmt.Errorf("failed to create HMAC: %w", err)
	}

	nonce := base64.StdEncoding.EncodeToString(append(firstHalf, createHMACResult.HMAC[:]...))
	return nonce, nil
}
