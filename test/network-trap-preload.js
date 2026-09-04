'use strict';
/**
 * Preload for child CLI processes: any network attempt throws.
 * Used by test/offline-network-trap.test.js so `node cli.js --key` cannot
 * quietly call app.coderifts.com.
 */
function trap(name) {
  return function trapped() {
    const err = new Error(`NETWORK_TRAP:${name}`);
    err.code = 'NETWORK_TRAP';
    throw err;
  };
}
globalThis.fetch = trap('fetch');
try {
  require('http').request = trap('http.request');
  require('https').request = trap('https.request');
} catch (_) { /* ignore */ }
