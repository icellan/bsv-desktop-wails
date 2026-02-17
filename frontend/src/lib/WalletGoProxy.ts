import {
  WalletInterface,
  OriginatorDomainNameStringUnder250Bytes,
  GetPublicKeyArgs,
  GetPublicKeyResult,
  RevealCounterpartyKeyLinkageArgs,
  RevealCounterpartyKeyLinkageResult,
  RevealSpecificKeyLinkageArgs,
  RevealSpecificKeyLinkageResult,
  WalletEncryptArgs,
  WalletEncryptResult,
  WalletDecryptArgs,
  WalletDecryptResult,
  CreateHmacArgs,
  CreateHmacResult,
  VerifyHmacArgs,
  VerifyHmacResult,
  CreateSignatureArgs,
  CreateSignatureResult,
  VerifySignatureArgs,
  VerifySignatureResult,
  CreateActionArgs,
  CreateActionResult,
  SignActionArgs,
  SignActionResult,
  AbortActionArgs,
  AbortActionResult,
  ListActionsArgs,
  ListActionsResult,
  InternalizeActionArgs,
  InternalizeActionResult,
  ListOutputsArgs,
  ListOutputsResult,
  RelinquishOutputArgs,
  RelinquishOutputResult,
  AcquireCertificateArgs,
  WalletCertificate,
  ListCertificatesArgs,
  ListCertificatesResult,
  ProveCertificateArgs,
  ProveCertificateResult,
  RelinquishCertificateArgs,
  RelinquishCertificateResult,
  DiscoverByIdentityKeyArgs,
  DiscoverByAttributesArgs,
  DiscoverCertificatesResult,
  AuthenticatedResult,
  GetHeightResult,
  GetHeaderArgs,
  GetHeaderResult,
  GetNetworkResult,
  GetVersionResult
} from '@bsv/sdk';

import { CallWalletMethod } from '../../wailsjs/go/main/WalletService';

/**
 * WalletGoProxy implements WalletInterface by proxying all calls to the Go
 * wallet backend via Wails bindings. This makes the Go wallet.Wallet the
 * single source of truth for all wallet operations.
 *
 * Both the frontend (via this proxy) and the HTTP server (directly) call
 * the same Go WalletService.CallWalletMethod().
 */
export class WalletGoProxy implements WalletInterface {

  private async call<T>(method: string, args: any, originator?: string): Promise<T> {
    const result = await CallWalletMethod(method, JSON.stringify(args), originator || '');
    return JSON.parse(result) as T;
  }

  async getPublicKey(
    args: GetPublicKeyArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<GetPublicKeyResult> {
    return this.call('getPublicKey', args, originator);
  }

  async revealCounterpartyKeyLinkage(
    args: RevealCounterpartyKeyLinkageArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<RevealCounterpartyKeyLinkageResult> {
    return this.call('revealCounterpartyKeyLinkage', args, originator);
  }

  async revealSpecificKeyLinkage(
    args: RevealSpecificKeyLinkageArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<RevealSpecificKeyLinkageResult> {
    return this.call('revealSpecificKeyLinkage', args, originator);
  }

  async encrypt(
    args: WalletEncryptArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<WalletEncryptResult> {
    return this.call('encrypt', args, originator);
  }

  async decrypt(
    args: WalletDecryptArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<WalletDecryptResult> {
    return this.call('decrypt', args, originator);
  }

  async createHmac(
    args: CreateHmacArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<CreateHmacResult> {
    return this.call('createHmac', args, originator);
  }

  async verifyHmac(
    args: VerifyHmacArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<VerifyHmacResult> {
    return this.call('verifyHmac', args, originator);
  }

  async createSignature(
    args: CreateSignatureArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<CreateSignatureResult> {
    return this.call('createSignature', args, originator);
  }

  async verifySignature(
    args: VerifySignatureArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<VerifySignatureResult> {
    return this.call('verifySignature', args, originator);
  }

  async createAction(
    args: CreateActionArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<CreateActionResult> {
    return this.call('createAction', args, originator);
  }

  async signAction(
    args: SignActionArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<SignActionResult> {
    return this.call('signAction', args, originator);
  }

  async abortAction(
    args: AbortActionArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<AbortActionResult> {
    return this.call('abortAction', args, originator);
  }

  async listActions(
    args: ListActionsArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<ListActionsResult> {
    return this.call('listActions', args, originator);
  }

  async internalizeAction(
    args: InternalizeActionArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<InternalizeActionResult> {
    return this.call('internalizeAction', args, originator);
  }

  async listOutputs(
    args: ListOutputsArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<ListOutputsResult> {
    return this.call('listOutputs', args, originator);
  }

  async relinquishOutput(
    args: RelinquishOutputArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<RelinquishOutputResult> {
    return this.call('relinquishOutput', args, originator);
  }

  async acquireCertificate(
    args: AcquireCertificateArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<WalletCertificate> {
    return this.call('acquireCertificate', args, originator);
  }

  async listCertificates(
    args: ListCertificatesArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<ListCertificatesResult> {
    return this.call('listCertificates', args, originator);
  }

  async proveCertificate(
    args: ProveCertificateArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<ProveCertificateResult> {
    return this.call('proveCertificate', args, originator);
  }

  async relinquishCertificate(
    args: RelinquishCertificateArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<RelinquishCertificateResult> {
    return this.call('relinquishCertificate', args, originator);
  }

  async discoverByIdentityKey(
    args: DiscoverByIdentityKeyArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<DiscoverCertificatesResult> {
    return this.call('discoverByIdentityKey', args, originator);
  }

  async discoverByAttributes(
    args: DiscoverByAttributesArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<DiscoverCertificatesResult> {
    return this.call('discoverByAttributes', args, originator);
  }

  async isAuthenticated(
    args: object,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<AuthenticatedResult> {
    return this.call('isAuthenticated', args, originator);
  }

  async waitForAuthentication(
    args: object,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<AuthenticatedResult> {
    return this.call('waitForAuthentication', args, originator);
  }

  async getHeight(
    args: object,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<GetHeightResult> {
    return this.call('getHeight', args, originator);
  }

  async getHeaderForHeight(
    args: GetHeaderArgs,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<GetHeaderResult> {
    return this.call('getHeaderForHeight', args, originator);
  }

  async getNetwork(
    args: object,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<GetNetworkResult> {
    return this.call('getNetwork', args, originator);
  }

  async getVersion(
    args: object,
    originator?: OriginatorDomainNameStringUnder250Bytes
  ): Promise<GetVersionResult> {
    return this.call('getVersion', args, originator);
  }
}
