package main

// This file imports the SDK wallet types that are used for JSON deserialization
// in the CallWalletMethod dispatcher. Since the Go SDK types already have proper
// JSON tags, we use them directly via type aliases.

import (
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
)

// Type aliases for SDK wallet arg types - used in CallWalletMethod
type (
	SDKCreateActionArgs                = sdk.CreateActionArgs
	SDKSignActionArgs                  = sdk.SignActionArgs
	SDKAbortActionArgs                 = sdk.AbortActionArgs
	SDKListActionsArgs                 = sdk.ListActionsArgs
	SDKInternalizeActionArgs           = sdk.InternalizeActionArgs
	SDKListOutputsArgs                 = sdk.ListOutputsArgs
	SDKRelinquishOutputArgs            = sdk.RelinquishOutputArgs
	SDKGetPublicKeyArgs                = sdk.GetPublicKeyArgs
	SDKRevealCounterpartyKeyLinkageArgs = sdk.RevealCounterpartyKeyLinkageArgs
	SDKRevealSpecificKeyLinkageArgs    = sdk.RevealSpecificKeyLinkageArgs
	SDKEncryptArgs                     = sdk.EncryptArgs
	SDKDecryptArgs                     = sdk.DecryptArgs
	SDKCreateHMACArgs                  = sdk.CreateHMACArgs
	SDKVerifyHMACArgs                  = sdk.VerifyHMACArgs
	SDKCreateSignatureArgs             = sdk.CreateSignatureArgs
	SDKVerifySignatureArgs             = sdk.VerifySignatureArgs
	SDKAcquireCertificateArgs          = sdk.AcquireCertificateArgs
	SDKListCertificatesArgs            = sdk.ListCertificatesArgs
	SDKProveCertificateArgs            = sdk.ProveCertificateArgs
	SDKRelinquishCertificateArgs       = sdk.RelinquishCertificateArgs
	SDKDiscoverByIdentityKeyArgs       = sdk.DiscoverByIdentityKeyArgs
	SDKDiscoverByAttributesArgs        = sdk.DiscoverByAttributesArgs
	SDKGetHeaderArgs                   = sdk.GetHeaderArgs
)
