import './fetchProxy';
import React from 'react';
import { createRoot } from 'react-dom/client';
import { UserInterface } from './lib/index';
import { wailsFunctions } from './wailsFunctions';

const rootElement = document.getElementById('root');
if (rootElement) {
  const root = createRoot(rootElement);

  root.render(
    <React.StrictMode>
      <UserInterface
        nativeHandlers={wailsFunctions}
        appVersion="0.1.0"
        appName="BSV Desktop"
      />
    </React.StrictMode>
  );
}
