/**
 * StorageWailsProxy - Frontend Storage Wrapper for Wails
 *
 * This class replaces StorageElectronIPC, implementing the same WalletStorageProvider
 * interface by delegating all storage operations to the Go backend via Wails bindings.
 *
 * Architecture:
 * - WebView: This class (implements WalletStorageProvider interface)
 * - Wails Bindings: Auto-generated TypeScript -> Go function calls
 * - Go Backend: GORM + SQLite storage via go-wallet-toolbox
 */

import type { WalletStorageProvider, WalletServices } from '@bsv/wallet-toolbox-client/out/src/sdk';
import { IsAvailable, MakeAvailable, InitializeServices, CallMethod } from '../../wailsjs/go/main/StorageProxyService';

export class StorageWailsProxy implements WalletStorageProvider {
  private identityKey: string;
  private chain: 'main' | 'test';
  private services?: WalletServices;
  private settings?: any;

  constructor(identityKey: string, chain: 'main' | 'test') {
    this.identityKey = identityKey;
    this.chain = chain;
    console.log('[StorageWailsProxy] Created for identity:', identityKey, 'chain:', chain);
  }

  setServices(v: WalletServices): void {
    this.services = v;
  }

  async initializeBackendServices(): Promise<void> {
    try {
      await InitializeServices(this.identityKey, this.chain);
      console.log('[StorageWailsProxy] Services initialized on backend');
    } catch (error) {
      throw new Error(`Failed to initialize services: ${error}`);
    }
  }

  isStorageProvider(): boolean {
    return false;
  }

  isAvailable(): boolean {
    return this.settings !== undefined;
  }

  getServices(): WalletServices {
    if (!this.services) {
      throw new Error('Services not set on StorageWailsProxy');
    }
    return this.services;
  }

  getSettings(): any {
    if (!this.settings) {
      throw new Error('Settings not available - call makeAvailable() first');
    }
    return this.settings;
  }

  canMakeAvailable(): boolean {
    return true;
  }

  async makeAvailable(): Promise<any> {
    console.log('[StorageWailsProxy] Making storage available...');
    try {
      const resultJSON = await MakeAvailable(this.identityKey, this.chain);
      this.settings = JSON.parse(resultJSON);
      console.log('[StorageWailsProxy] Storage available, settings:', this.settings);
      return this.settings;
    } catch (error) {
      throw new Error(`Failed to make storage available: ${error}`);
    }
  }

  private async callMethod<T>(method: string, ...args: any[]): Promise<T> {
    try {
      const resultJSON = await CallMethod(
        this.identityKey,
        this.chain,
        method,
        JSON.stringify(args)
      );
      return JSON.parse(resultJSON) as T;
    } catch (error) {
      throw new Error(`Storage method ${method} failed: ${error}`);
    }
  }

  // ===== WalletStorageProvider Interface Methods =====

  async insertCertificate(...args: any[]): Promise<any> { return this.callMethod('insertCertificate', ...args); }
  async updateCertificate(...args: any[]): Promise<any> { return this.callMethod('updateCertificate', ...args); }
  async findCertificates(...args: any[]): Promise<any> { return this.callMethod('findCertificates', ...args); }
  async deleteCertificate(...args: any[]): Promise<any> { return this.callMethod('deleteCertificate', ...args); }

  async insertOutput(...args: any[]): Promise<any> { return this.callMethod('insertOutput', ...args); }
  async updateOutput(...args: any[]): Promise<any> { return this.callMethod('updateOutput', ...args); }
  async findOutputs(...args: any[]): Promise<any> { return this.callMethod('findOutputs', ...args); }
  async deleteOutput(...args: any[]): Promise<any> { return this.callMethod('deleteOutput', ...args); }

  async insertTransaction(...args: any[]): Promise<any> { return this.callMethod('insertTransaction', ...args); }
  async updateTransaction(...args: any[]): Promise<any> { return this.callMethod('updateTransaction', ...args); }
  async findTransactions(...args: any[]): Promise<any> { return this.callMethod('findTransactions', ...args); }
  async deleteTransaction(...args: any[]): Promise<any> { return this.callMethod('deleteTransaction', ...args); }

  async insertCommission(...args: any[]): Promise<any> { return this.callMethod('insertCommission', ...args); }
  async findCommissions(...args: any[]): Promise<any> { return this.callMethod('findCommissions', ...args); }

  async insertOutputBasket(...args: any[]): Promise<any> { return this.callMethod('insertOutputBasket', ...args); }
  async updateOutputBasket(...args: any[]): Promise<any> { return this.callMethod('updateOutputBasket', ...args); }
  async findOutputBaskets(...args: any[]): Promise<any> { return this.callMethod('findOutputBaskets', ...args); }
  async deleteOutputBasket(...args: any[]): Promise<any> { return this.callMethod('deleteOutputBasket', ...args); }

  async insertProvenTx(...args: any[]): Promise<any> { return this.callMethod('insertProvenTx', ...args); }
  async updateProvenTx(...args: any[]): Promise<any> { return this.callMethod('updateProvenTx', ...args); }
  async findProvenTxs(...args: any[]): Promise<any> { return this.callMethod('findProvenTxs', ...args); }
  async deleteProvenTx(...args: any[]): Promise<any> { return this.callMethod('deleteProvenTx', ...args); }

  async insertProvenTxReq(...args: any[]): Promise<any> { return this.callMethod('insertProvenTxReq', ...args); }
  async updateProvenTxReq(...args: any[]): Promise<any> { return this.callMethod('updateProvenTxReq', ...args); }
  async findProvenTxReqs(...args: any[]): Promise<any> { return this.callMethod('findProvenTxReqs', ...args); }
  async deleteProvenTxReq(...args: any[]): Promise<any> { return this.callMethod('deleteProvenTxReq', ...args); }

  async insertTxLabel(...args: any[]): Promise<any> { return this.callMethod('insertTxLabel', ...args); }
  async findTxLabels(...args: any[]): Promise<any> { return this.callMethod('findTxLabels', ...args); }
  async deleteTxLabel(...args: any[]): Promise<any> { return this.callMethod('deleteTxLabel', ...args); }

  async insertOutputTag(...args: any[]): Promise<any> { return this.callMethod('insertOutputTag', ...args); }
  async findOutputTags(...args: any[]): Promise<any> { return this.callMethod('findOutputTags', ...args); }
  async deleteOutputTag(...args: any[]): Promise<any> { return this.callMethod('deleteOutputTag', ...args); }

  async insertCounterparty(...args: any[]): Promise<any> { return this.callMethod('insertCounterparty', ...args); }
  async updateCounterparty(...args: any[]): Promise<any> { return this.callMethod('updateCounterparty', ...args); }
  async findCounterparties(...args: any[]): Promise<any> { return this.callMethod('findCounterparties', ...args); }
  async deleteCounterparty(...args: any[]): Promise<any> { return this.callMethod('deleteCounterparty', ...args); }

  async processSyncChunk(...args: any[]): Promise<any> { return this.callMethod('processSyncChunk', ...args); }
  async requestSyncChunk(...args: any[]): Promise<any> { return this.callMethod('requestSyncChunk', ...args); }

  async getWalletStatus(...args: any[]): Promise<any> { return this.callMethod('getWalletStatus', ...args); }
  async getHeight(...args: any[]): Promise<any> { return this.callMethod('getHeight', ...args); }
  async updateHeight(...args: any[]): Promise<any> { return this.callMethod('updateHeight', ...args); }

  async findPermissions(...args: any[]): Promise<any> { return this.callMethod('findPermissions', ...args); }
  async insertPermission(...args: any[]): Promise<any> { return this.callMethod('insertPermission', ...args); }
  async updatePermission(...args: any[]): Promise<any> { return this.callMethod('updatePermission', ...args); }
  async deletePermission(...args: any[]): Promise<any> { return this.callMethod('deletePermission', ...args); }

  async findSettings(...args: any[]): Promise<any> { return this.callMethod('findSettings', ...args); }
  async insertSetting(...args: any[]): Promise<any> { return this.callMethod('insertSetting', ...args); }
  async updateSetting(...args: any[]): Promise<any> { return this.callMethod('updateSetting', ...args); }
  async deleteSetting(...args: any[]): Promise<any> { return this.callMethod('deleteSetting', ...args); }

  // ===== WalletStorageWriter Methods =====

  async destroy(): Promise<void> { return this.callMethod('destroy'); }
  async migrate(...args: any[]): Promise<any> { return this.callMethod('migrate', ...args); }
  async findOrInsertUser(...args: any[]): Promise<any> { return this.callMethod('findOrInsertUser', ...args); }
  async abortAction(...args: any[]): Promise<any> { return this.callMethod('abortAction', ...args); }
  async createAction(...args: any[]): Promise<any> { return this.callMethod('createAction', ...args); }
  async processAction(...args: any[]): Promise<any> { return this.callMethod('processAction', ...args); }
  async internalizeAction(...args: any[]): Promise<any> { return this.callMethod('internalizeAction', ...args); }
  async insertCertificateAuth(...args: any[]): Promise<any> { return this.callMethod('insertCertificateAuth', ...args); }
  async relinquishCertificate(...args: any[]): Promise<any> { return this.callMethod('relinquishCertificate', ...args); }
  async relinquishOutput(...args: any[]): Promise<any> { return this.callMethod('relinquishOutput', ...args); }

  // ===== WalletStorageReader Methods =====

  async findCertificatesAuth(...args: any[]): Promise<any> { return this.callMethod('findCertificatesAuth', ...args); }
  async findOutputBasketsAuth(...args: any[]): Promise<any> { return this.callMethod('findOutputBasketsAuth', ...args); }
  async findOutputsAuth(...args: any[]): Promise<any> { return this.callMethod('findOutputsAuth', ...args); }
  async listActions(...args: any[]): Promise<any> { return this.callMethod('listActions', ...args); }
  async listCertificates(...args: any[]): Promise<any> { return this.callMethod('listCertificates', ...args); }
  async listOutputs(...args: any[]): Promise<any> { return this.callMethod('listOutputs', ...args); }

  // ===== WalletStorageSync Methods =====

  async findOrInsertSyncStateAuth(...args: any[]): Promise<any> { return this.callMethod('findOrInsertSyncStateAuth', ...args); }
  async setActive(...args: any[]): Promise<any> { return this.callMethod('setActive', ...args); }
  async getSyncChunk(...args: any[]): Promise<any> { return this.callMethod('getSyncChunk', ...args); }
}
