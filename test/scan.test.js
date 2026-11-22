'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { scanText, isPlaceholder } = require('../src/scan');
const { fake } = require('./helpers');

const ids = (text, file) => scanText(text, file).map((f) => f.rule).sort();

test('detects Binance key + secret in .env style', () => {
  const t = `BINANCE_API_KEY=${fake.binance()}\nBINANCE_API_SECRET="${fake.binance()}"\n`;
  assert.deepStrictEqual(ids(t), ['binance-api-credential', 'binance-api-credential']);
});

test('detects ccxt config block (exchange name on a line above)', () => {
  const t = `const ex = new ccxt.binance({\n  apiKey: '${fake.binance()}',\n  secret: '${fake.binance()}',\n});`;
  assert.strictEqual(ids(t).length, 2);
});

test('detects Bybit key and secret', () => {
  const t = `bybit:\n  api_key: ${fake.bybitKey()}\n  api_secret: ${fake.bybitSecret()}\n`;
  assert.deepStrictEqual(ids(t), ['bybit-api-key', 'bybit-api-secret']);
});

test('detects OKX key (UUID) and secret (uppercase hex)', () => {
  const t = `{"okx": {"apiKey": "${fake.okxKey()}", "secret": "${fake.okxSecret()}"}}`;
  assert.deepStrictEqual(ids(t), ['okx-api-key', 'okx-api-secret']);
});

test('detects Bitget bg_ key without context, secret with context', () => {
  assert.deepStrictEqual(ids(`token = "${fake.bitgetKey()}"`), ['bitget-api-key']);
  assert.deepStrictEqual(ids(`BITGET_SECRET=${fake.bitgetSecret()}`), ['bitget-api-secret']);
});

test('uses the file name as context (binance.env)', () => {
  assert.strictEqual(ids(`API_KEY=${fake.binance()}`, '/x/binance.env').length, 1);
});

test('never returns the full secret', () => {
  const v = fake.binance();
  const f = scanText(`BINANCE_API_KEY=${v}`)[0];
  assert.ok(!JSON.stringify(f).includes(v));
  assert.ok(!JSON.stringify(f).includes(v.slice(4, 20)));
});

test('links carry the npm UTM and point to quantaira.app', () => {
  const f = scanText(`BINANCE_API_KEY=${fake.binance()}`)[0];
  for (const u of [f.learnMore, f.leakResponse]) {
    assert.match(u, /^https:\/\/quantaira\.app\/[a-z0-9-]+\?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor$/);
  }
});

// ---- false-positive guards ----
test('ignores 64-char values with no exchange context', () => {
  assert.deepStrictEqual(ids(`API_KEY=${fake.binance()}\nSOME_TOKEN=${fake.binance()}`), []);
});

test('ignores git SHAs / sha256 hashes even near the word binance', () => {
  const sha256 = require('node:crypto').createHash('sha256').update('x').digest('hex');
  assert.deepStrictEqual(ids(`# binance release\nintegrity: ${sha256}\ncommit = ${sha256.slice(0, 40)}`), []);
});

test('ignores placeholders', () => {
  const t = [
    'BINANCE_API_KEY=your_binance_api_key_here',
    `BINANCE_API_KEY=${'a'.repeat(64)}`,
    `BINANCE_API_KEY=${'abcd'.repeat(16)}`,
    `BINANCE_SECRET=${'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB'}`,
    'BINANCE_API_KEY=${BINANCE_API_KEY}',
    'apiKey: process.env.BINANCE_API_KEY',
    `bybit_api_key = "XXXXXXXXXXXXXXXXXX"`,
    `okx apiKey: "00000000-0000-0000-0000-000000000000"`,
  ].join('\n');
  assert.deepStrictEqual(ids(t), []);
});

test('ignores prose and longer tokens', () => {
  const v = fake.binance();
  assert.deepStrictEqual(ids('Rotate your Binance API key in the security settings.'), []);
  assert.deepStrictEqual(ids(`BINANCE_API_KEY=${v}EXTRA`), []);
  assert.deepStrictEqual(ids(`bybit key=${fake.bybitKey()}abc`), []);
});

test('ignores Bitget-shaped secret without bitget context', () => {
  assert.deepStrictEqual(ids(`SECRET=${fake.bitgetSecret()}`), []);
});

test('OKX secret must be uppercase hex', () => {
  assert.deepStrictEqual(ids(`OKX_SECRET=${fake.okxSecret().toLowerCase()}`), []);
});

test('isPlaceholder', () => {
  assert.ok(isPlaceholder('0'.repeat(32)));
  assert.ok(isPlaceholder('your-key'));
  assert.ok(!isPlaceholder(fake.binance()));
});

test('inline allow comment skips a line', () => {
  assert.deepStrictEqual(ids(`BINANCE_API_KEY=${fake.binance()} # exchange-key-doctor:allow`), []);
});
