// Wails native handlers that replace Electron IPC calls
// These call Go methods bound via Wails runtime

import { IsFocused, RequestFocus, RelinquishFocus, DownloadFile, SaveMnemonic } from '../wailsjs/go/main/NativeService';

export async function isFocused(): Promise<boolean> {
  try {
    return await IsFocused();
  } catch {
    return false;
  }
}

export async function onFocusRequested(): Promise<void> {
  try {
    await RequestFocus();
  } catch (error) {
    console.error('Focus request failed:', error);
  }
}

export async function onFocusRelinquished(): Promise<void> {
  try {
    await RelinquishFocus();
  } catch (error) {
    console.error('Relinquish focus failed:', error);
  }
}

export async function onDownloadFile(fileData: Blob, fileName: string): Promise<boolean> {
  try {
    const arrayBuffer = await fileData.arrayBuffer();
    const content = Array.from(new Uint8Array(arrayBuffer));
    const result = await DownloadFile(fileName, content);
    return result.success;
  } catch (error) {
    console.error('Download failed:', error);
    return false;
  }
}

export async function saveMnemonic(mnemonic: string): Promise<{ success: boolean; path?: string; error?: string }> {
  try {
    const result = await SaveMnemonic(mnemonic);
    return result;
  } catch (error) {
    console.error('Save mnemonic failed:', error);
    return { success: false, error: String(error) };
  }
}

// Bundled export for UserInterface component
export const wailsFunctions = {
  isFocused,
  onFocusRequested,
  onFocusRelinquished,
  onDownloadFile,
  saveMnemonic
};
