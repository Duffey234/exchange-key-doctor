'use strict';
const { link } = require('./links');

// Exchange error codes that usually mean "the API key setup is wrong".
const CODES = {
  binance: {
    '-2015': { msg: 'Invalid API-key, IP, or permissions for action', page: 'binance2015', hint: 'Check the IP whitelist, that the key has the permission this call needs, and that you are not mixing testnet and live keys.' },
    '-2014': { msg: 'API-key format invalid', page: 'binance2015', hint: 'The key was copied with extra spaces/quotes or is truncated. Re-copy it or create a new key.' },
    '-1022': { msg: 'Signature for this request is not valid', page: 'binance2015', hint: 'The secret is wrong, or the query string you signed is not the one you sent.' },
  },
  bybit: {
    '10003': { msg: 'API key is invalid', page: 'bybit10003', hint: 'Wrong key, deleted key, or a testnet key used against mainnet (or the reverse).' },
    '10004': { msg: 'Error sign', page: 'bybit10003', hint: 'The secret is wrong or the signed payload does not match the request.' },
    '10010': { msg: 'Unmatched IP', page: 'bybit10003', hint: 'Your server IP is not in the key\'s IP whitelist.' },
    '33004': { msg: 'API key expired', page: 'bybitExpired', hint: 'Keys without an IP whitelist expire. Create a new key and bind your server IP.' },
  },
  okx: {
    '50119': { msg: 'API key doesn\'t exist', page: 'okx50119', hint: 'Deleted key, a demo-trading key on live (or the reverse), or a typo.' },
    '50111': { msg: 'Invalid OK-ACCESS-KEY', page: 'okx50119', hint: 'Re-copy the key; check demo vs live.' },
    '50113': { msg: 'Invalid sign', page: 'okx50119', hint: 'Wrong secret, or timestamp/method/path in the signature do not match.' },
    '50105': { msg: 'Wrong OK-ACCESS-PASSPHRASE', page: 'okx50119', hint: 'The passphrase is the one you typed when creating the key, not your login password.' },
  },
  bitget: {
    '40012': { msg: 'apikey/password is incorrect', page: 'bitgetPassphrase', hint: 'Usually the passphrase. Bitget cannot recover it: delete the key and create a new one.' },
    '40006': { msg: 'Invalid ACCESS_KEY', page: 'checker', hint: 'Re-copy the key (it starts with bg_).' },
    '40037': { msg: 'Apikey does not exist', page: 'checker', hint: 'Deleted key, a demo key on live (or the reverse), or a typo. Re-copy it or create a new one.' },
    '40009': { msg: 'sign signature error', page: 'checker', hint: 'Wrong secret or the signed string does not match the request.' },
  },
};

function explain(exchange, code) {
  const ex = String(exchange || '').toLowerCase();
  const table = CODES[ex];
  if (!table) return null;
  const c = String(code).trim();
  const entry = table[c] || (ex === 'binance' && table[`-${c.replace(/^-/, '')}`]);
  if (!entry) return null;
  return { exchange: ex, code: c, ...entry, learnMore: link(entry.page) };
}

module.exports = { explain, CODES };
