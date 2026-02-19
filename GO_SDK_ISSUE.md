# Issue: CertificateType/SerialNumber base64 encoding incompatible with TS SDK ecosystem

**Repo:** bsv-blockchain/go-wallet-toolbox (and bsv-blockchain/go-sdk)

## Summary

The Go SDK's `CertificateType` and `SerialNumber` types use `[32]byte` with strict JSON marshaling that is incompatible with the TypeScript SDK ecosystem. This causes two categories of failures:

1. **JSON unmarshal rejects short base64 values** — The TS SDK allows certificate types shorter than 32 bytes (e.g., `"CommonSource identity"` = 21 bytes), but `Bytes32Base64.UnmarshalJSON` requires exactly 32 bytes.
2. **Re-encoded types don't match originals** — When `[32]byte` is base64-encoded for outgoing requests (e.g., to certifiers), trailing zero-pad bytes produce a different base64 string than the original, causing remote services to reject requests.

## Reproduction

### Error 1: Unmarshal failure
An external app calls `listCertificates` via the BRC-100 HTTP API with:
```json
{"certifiers": [], "types": ["Q29tbW9uU291cmNlIGlkZW50aXR5"], "limit": 100}
```

The type `Q29tbW9uU291cmNlIGlkZW50aXR5` decodes to `"CommonSource identity"` (21 bytes). The Go SDK rejects this with:
```
expected 32 bytes, got 21
```

**Root cause**: `Bytes32Base64.UnmarshalJSON` in `wallet/encoding.go:70`:
```go
if len(decoded) != 32 {
    return fmt.Errorf("expected 32 bytes, got %d", len(decoded))
}
```

### Error 2: Type mismatch with certifiers
After working around Error 1 (by zero-padding to 32 bytes before unmarshal), `acquireCertificate` calls a remote certifier at `{certifierUrl}/signCertificate`. The Go SDK re-encodes the type from `[32]byte`:

```go
// wallet_acquire_certificate_issuance.go:139
certTypeB64 := base64.StdEncoding.EncodeToString(p.Args.Type[:])
```

This produces `Q29tbW9uU291cmNlIGlkZW50aXR5AAAAAAAAAAAAAAA=` (32 bytes with 11 trailing zeros) instead of the original `Q29tbW9uU291cmNlIGlkZW50aXR5` (21 bytes). The certifier rejects this because the type doesn't match its registered certificate types.

## Comparison with TypeScript SDK

In the TypeScript SDK (`@bsv/sdk`), `ListCertificatesArgs.types` is `Base64String[]` — arbitrary-length base64 strings with no fixed-size requirement. Certificate types like `"CommonSource identity"` are encoded as-is without zero-padding.

The Electron version of BSV Desktop uses the TS wallet (`@bsv/wallet-toolbox-client`) which handles these types natively. The Go port hits this incompatibility when the Go wallet communicates with TS-based certifiers and apps.

## Affected Code Locations

All these locations encode `CertificateType` or `SerialNumber` from `[32]byte` to base64, producing zero-padded output:

| File | Line | Context |
|------|------|---------|
| `wallet/encoding.go` | 57, 70 | `Bytes32Base64` Marshal/Unmarshal |
| `wallet/encoding.go` | 121 | `StringBase64FromArray` |
| `wallet/interfaces.go` | 111 | `CertificateType.Base64()` |
| `wallet/internal/actions/wallet_acquire_certificate_issuance.go` | 139 | Certifier request body |
| `wallet/wallet.go` | 886-887 | Direct cert insert (Type, SerialNumber) |
| `wallet/wallet.go` | 990, 1031 | ProveCertificate serial number |
| `wallet/internal/mapping/mapping_relinquish_certificate_args.go` | 26-27 | Relinquish cert mapping |
| `wallet/internal/mapping/mapping_list_certificates_args.go` | 18 | List certs type mapping |
| `auth/utils/validate_certificates.go` | 27, 44 | Certificate validation |
| `auth/utils/certificate_debug.go` | 98-99 | Debug logging |

## Suggested Fix

1. **`Bytes32Base64.UnmarshalJSON`**: Accept `<= 32` bytes (zero-pad shorter values), matching the existing `CertificateTypeFromBase64()` behavior which already allows this.

2. **`Bytes32Base64.MarshalJSON`** and all manual `base64.StdEncoding.EncodeToString(x[:])` calls: Trim trailing zero bytes before encoding:
```go
func TrimmedBase64(b [32]byte) string {
    trimmed := bytes.TrimRight(b[:], "\x00")
    if len(trimmed) == 0 {
        trimmed = b[:]
    }
    return base64.StdEncoding.EncodeToString(trimmed)
}
```

This ensures round-trip compatibility: a short base64 string from the TS ecosystem unmarshals into `[32]byte` (zero-padded) and marshals back to the original short base64 string.

## Additional Finding: BRC-104 HMAC Incompatibility

After fixing the type encoding (via vendored patches), `acquireCertificate` with `acquisitionProtocol: "issuance"` progresses further but fails with:
```
Nonce verification error: HMAC is not valid
```

This suggests a separate compatibility issue in the BRC-104 mutual authentication between the Go SDK's `auth.Peer` and TS-based certifiers. The Go wallet's HMAC of the nonce cannot be verified by the certifier.

## Environment
- go-wallet-toolbox v0.172.1
- go-sdk v1.2.18
- Certifier: `https://cert.commonsource.nl` (TypeScript-based)
