'use strict';
// Generate random key-shaped values at test time so no key-shaped strings are committed.
const crypto = require('node:crypto');
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
function rand(alphabet, n) {
  const b = crypto.randomBytes(n);
  let s = '';
  for (let i = 0; i < n; i++) s += alphabet[b[i] % alphabet.length];
  return s;
}
const fake = {
  binance: () => rand(ALNUM, 64),
  bybitKey: () => rand(ALNUM, 18),
  bybitSecret: () => rand(ALNUM, 36),
  okxKey: () => crypto.randomUUID(),
  okxSecret: () => rand('0123456789ABCDEF', 32),
  bitgetKey: () => `bg_${rand('0123456789abcdef', 32)}`,
  bitgetSecret: () => rand('0123456789abcdef', 64),
};
module.exports = { fake, rand };
