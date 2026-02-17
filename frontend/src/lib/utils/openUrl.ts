import { BrowserOpenURL } from '../../../wailsjs/runtime/runtime';

/**
 * Opens a URL in the system's default browser using the Wails runtime.
 */
export async function openUrl(url: string): Promise<void> {
  try {
    BrowserOpenURL(url);
  } catch (error) {
    console.error('Error opening URL:', error);
    // Fallback to window.open
    window.open(url, '_blank', 'noopener,noreferrer');
  }
}
