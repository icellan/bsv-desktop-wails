// Global type declarations for Wails runtime
// The Wails-generated bindings in wailsjs/ provide type-safe access to Go methods.
// This file provides additional global type augmentations as needed.

declare global {
  interface Window {
    // Wails runtime is injected automatically
    runtime?: any;
  }
}

export {};
