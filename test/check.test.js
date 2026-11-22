'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { buildRequest, analyze, checkKey, HOSTS } = require('../src/check');

test('Binance signature matches the official docs example vector', () => {
  // From Binance API docs (SIGNED endpoint examples).
  const secret = 'NhqPtmdSJYdKjVHjA7PZj4Mge3R5YNiP1e3UZjInClVN65XAbvqqM6A7H5fATj0j'; // public docs vector, exchange-key-doctor:allow
  const qs = 'symbol=LTCBTC&side=BUY&type=LIMIT&timeInForce=GTC&quantity=1&price=0.1&recvWindow=5000&timestamp=1499827319559';
  const sig = crypto.createHmac('sha256', secret).update(qs).digest('hex');
  assert.strictEqual(sig, 'c8db56825ae71d6d79447849e617115f4a920fa2acdcab2b053c4b2838bd6b71');
});

test('Binance request: signed GET to apiRestrictions on api.binance.com', () => {
  const r = buildRequest('binance', { key: 'K', secret: 'S' }, 1700000000000);
  const qs = 'recvWindow=5000&timestamp=1700000000000';
  const sig = crypto.createHmac('sha256', 'S').update(qs).digest('hex');
  assert.strictEqual(r.url, `https://api.binance.com/sapi/v1/account/apiRestrictions?${qs}&signature=${sig}`);
  assert.deepStrictEqual(r.headers, { 'X-MBX-APIKEY': 'K' });
  assert.ok(!r.url.includes('S&') && !r.url.includes('=S'));
});

test('Bybit, OKX, Bitget requests hit only their own read-only endpoints', () => {
  const b = buildRequest('bybit', { key: 'K', secret: 'S' }, 1);
  assert.strictEqual(b.url, 'https://api.bybit.com/v5/user/query-api');
  assert.strictEqual(b.headers['X-BAPI-SIGN'], crypto.createHmac('sha256', 'S').update('1K5000').digest('hex'));
  const o = buildRequest('okx', { key: 'K', secret: 'S', passphrase: 'P' }, 0);
  assert.strictEqual(o.url, 'https://www.okx.com/api/v5/account/config');
  assert.strictEqual(o.headers['OK-ACCESS-SIGN'], crypto.createHmac('sha256', 'S').update('1970-01-01T00:00:00.000ZGET/api/v5/account/config').digest('base64'));
  const g = buildRequest('bitget', { key: 'K', secret: 'S', passphrase: 'P' }, 5);
  assert.strictEqual(g.url, 'https://api.bitget.com/api/v2/spot/account/info');
  assert.strictEqual(g.headers['ACCESS-SIGN'], crypto.createHmac('sha256', 'S').update('5GET/api/v2/spot/account/info').digest('base64'));
  for (const r of [b, o, g]) for (const v of Object.values(r.headers)) assert.notStrictEqual(v, 'S');
});

test('analyze Binance: withdrawals on => CRITICAL, no IP => WARN', () => {
  const r = analyze('binance', { enableWithdrawals: true, ipRestrict: false, enableReading: true });
  assert.ok(r.some((x) => x.level === 'CRITICAL' && /withdraw/i.test(x.title)));
  assert.ok(r.some((x) => x.level === 'WARN' && /IP/.test(x.title)));
  const good = analyze('binance', { enableWithdrawals: false, ipRestrict: true });
  assert.ok(good.every((x) => x.level === 'OK'));
});

test('analyze Binance error -2015 links to the fix page', () => {
  const r = analyze('binance', { code: -2015, msg: 'Invalid API-key, IP, or permissions for action.' });
  assert.strictEqual(r[0].level, 'ERROR');
  assert.match(r[0].learnMore, /quantaira\.app\/binance-error-2015\?utm_source=npm/);
});

test('analyze Bybit / OKX / Bitget withdraw flags', () => {
  assert.ok(analyze('bybit', { retCode: 0, result: { readOnly: 0, ips: [], permissions: { Wallet: ['Withdraw'] } } }).some((x) => x.level === 'CRITICAL'));
  assert.ok(analyze('bybit', { retCode: 0, result: { readOnly: 0, ips: ['1.2.3.4'], permissions: { Wallet: [] } } }).every((x) => x.level === 'OK'));
  assert.match(analyze('bybit', { retCode: 10003, retMsg: 'API key is invalid.' })[0].learnMore, /bybit-error-10003/);
  assert.ok(analyze('okx', { code: '0', data: [{ perm: 'read_only,trade,withdraw', ip: '' }] }).some((x) => x.level === 'CRITICAL'));
  assert.match(analyze('okx', { code: '50119', msg: "API key doesn't exist" })[0].learnMore, /okx-api-key-doesnt-exist/);
  assert.ok(analyze('bitget', { code: '00000', data: { authorities: ['stow', 'wwow'], ips: '' } }).some((x) => x.level === 'CRITICAL'));
  assert.match(analyze('bitget', { code: '40012', msg: 'apikey/password is incorrect' })[0].learnMore, /bitget-forgot-api-passphrase/);
});

test('unknown error messages are sanitized (no long tokens echoed)', () => {
  const r = analyze('binance', { code: -9999, msg: 'bad key AbCdEfGhIjKlMnOpQrStUv' });
  assert.ok(!r[0].title.includes('AbCdEfGhIjKlMnOpQrStUv'));
});

test('checkKey: reads env, calls ONLY the exchange host, returns no secrets', async () => {
  const calls = [];
  const env = { BINANCE_API_KEY: 'k'.repeat(64), BINANCE_API_SECRET: 'SECRETVALUE123' };
  const fetchImpl = async (url, opts) => {
    calls.push({ url, opts });
    return { json: async () => ({ enableWithdrawals: false, ipRestrict: true }) };
  };
  const res = await checkKey('binance', { env, fetchImpl, now: 1 });
  assert.strictEqual(calls.length, 1);
  assert.ok(calls[0].url.startsWith(HOSTS.binance + '/sapi/v1/account/apiRestrictions?'));
  assert.strictEqual(calls[0].opts.method, 'GET');
  assert.strictEqual(calls[0].opts.redirect, 'error');
  assert.ok(!calls[0].url.includes('SECRETVALUE123'));
  assert.ok(!JSON.stringify(res).includes('SECRETVALUE123') && !JSON.stringify(res).includes('k'.repeat(64)));
});

test('checkKey: missing env gives a clear error and makes no request', async () => {
  let called = false;
  await assert.rejects(checkKey('okx', { env: {}, fetchImpl: async () => { called = true; } }), /OKX_API_KEY/);
  assert.strictEqual(called, false);
});

test('regional block (HTTP 451/403) is reported, never treated as a pass', () => {
  const r = analyze('binance', { code: 0, msg: 'Service unavailable from a restricted location' }, 451);
  assert.strictEqual(r.length, 1);
  assert.strictEqual(r[0].level, 'ERROR');
  assert.match(r[0].title, /regional block/);
  assert.strictEqual(analyze('bybit', {}, 403)[0].level, 'ERROR');
});

test('unexpected bodies are ERROR, not OK', () => {
  for (const ex of ['binance', 'bybit', 'okx', 'bitget']) {
    const r = analyze(ex, { hello: 1 }, 200);
    assert.strictEqual(r[0].level, 'ERROR', ex);
    assert.ok(!r.some((x) => x.level === 'OK'), ex);
  }
});
