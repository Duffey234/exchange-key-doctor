'use strict';
// Every link the CLI prints. All pages are free guides on quantaira.app.
const BASE = 'https://quantaira.app/';
const UTM = 'utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor';

const PAGES = {
  checker: 'api-key-safety-checker',
  permissions: 'trading-bot-api-key-permissions',
  leakTracker: 'api-key-leak-tracker',
  leak3commas: '3commas-api-key-leak',
  aiAgents: 'is-it-safe-to-give-api-key-to-claude',
  redFlags: 'crypto-trading-bot-scam-red-flags',
  binance2015: 'binance-error-2015',
  bybit10003: 'bybit-error-10003',
  bybitExpired: 'bybit-api-key-expired',
  bitgetPassphrase: 'bitget-forgot-api-passphrase',
  okx50119: 'okx-api-key-doesnt-exist',
};

function link(page) {
  const slug = PAGES[page];
  if (!slug) throw new Error(`unknown page: ${page}`);
  return `${BASE}${slug}?${UTM}`;
}

module.exports = { link, PAGES, BASE, UTM };
