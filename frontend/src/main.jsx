import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

// Defensive safety handler to prevent duplicate third-party extension relay collisions from halting the application
if (typeof window !== 'undefined') {
  const originalErrorHandler = window.onerror;
  window.onerror = function (message, source, lineno, colno, error) {
    if (typeof message === 'string' && message.toLowerCase().includes('relay with the name')) {
      console.warn('[CyberTrace System]: Suppressed duplicate external relay extension registration collision:', message);
      return true;
    }
    if (originalErrorHandler) {
      return originalErrorHandler.apply(this, arguments);
    }
    return false;
  };

  window.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason;
    const msg = (reason?.message || String(reason || '')).toLowerCase();
    if (msg.includes('relay with the name')) {
      event.preventDefault();
      console.warn('[CyberTrace System]: Handled duplicate external relay rejection:', reason);
    }
  });
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)

