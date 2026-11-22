'use strict';
// Opt-in, local, read-only permission check.
// - Credentials are read from environment variables only.
// - They are sent ONLY to the exchange's own read-only "what can this key do" endpoint (HOSTS below).
// - Credentials and raw responses are never printed or written anywhere; only derived flags are returned.
const crypto = require('node:crypto');
const { link } = require('./links');
const { explain } = require('./explain');

const HOSTS = {
  binance: 'https://api.binance.com',
  bybit: 'https://api.bybit.com',
  okx: 'https://www.okx.com',
  bitget: 'https://api.bitget.com',
};
const PATHS = {
  binance: '/sapi/v1/account/apiRestrictions',
  bybit: '/v5/user/query-api',
  okx: '/api/v5/account/config',
  bitget: '/api/v2/spot/account/info',
};
const ENV = {
  binance: ['BINANCE_API_KEY', 'BINANCE_API_SECRET'],
  bybit: ['BYBIT_API_KEY', 'BYBIT_API_SECRET'],
  okx: ['OKX_API_KEY', 'OKX_API_SECRET', 'OKX_API_PASSPHRASE'],
  bitget: ['BITGET_API_KEY', 'BITGET_API_SECRET', 'BITGET_API_PASSPHRASE'],
};

const hmacHex = (secret, msg) => crypto.createHmac('sha256', secret).update(msg).digest('hex');
const hmacB64 = (secret, msg) => crypto.createHmac('sha256', secret).update(msg).digest('base64');

function readCreds(exchange, env) {
  const names = ENV[exchange];
  const vals = names.map((n) => (env[n] || '').trim());
  const missing = names.filter((_, i) => !vals[i]);
  if (missing.length) {
    const e = new Error(`missing environment variable(s): ${missing.join(', ')}`);
    e.code = 'MISSING_ENV';
    throw e;
  }
  return { key: vals[0], secret: vals[1], passphrase: vals[2] };
}

// Build the signed request. Pure function (testable without network).
function buildRequest(exchange, creds, now = Date.now()) {
  const url = HOSTS[exchange] + PATHS[exchange];
  switch (exchange) {
    case 'binance': {
      const qs = `recvWindow=5000&timestamp=${now}`;
      return { url: `${url}?${qs}&signature=${hmacHex(creds.secret, qs)}`, headers: { 'X-MBX-APIKEY': creds.key } };
    }
    case 'bybit': {
      const recv = '5000';
      const sign = hmacHex(creds.secret, `${now}${creds.key}${recv}`);
      return { url, headers: { 'X-BAPI-API-KEY': creds.key, 'X-BAPI-TIMESTAMP': String(now), 'X-BAPI-RECV-WINDOW': recv, 'X-BAPI-SIGN': sign } };
    }
    case 'okx': {
      const ts = new Date(now).toISOString();
      const sign = hmacB64(creds.secret, `${ts}GET${PATHS.okx}`);
      return { url, headers: { 'OK-ACCESS-KEY': creds.key, 'OK-ACCESS-SIGN': sign, 'OK-ACCESS-TIMESTAMP': ts, 'OK-ACCESS-PASSPHRASE': creds.passphrase } };
    }
    case 'bitget': {
      const ts = String(now);
      const sign = hmacB64(creds.secret, `${ts}GET${PATHS.bitget}`);
      return { url, headers: { 'ACCESS-KEY': creds.key, 'ACCESS-SIGN': sign, 'ACCESS-TIMESTAMP': ts, 'ACCESS-PASSPHRASE': creds.passphrase, locale: 'en-US', 'Content-Type': 'application/json' } };
    }
    default:
      throw new Error(`unsupported exchange: ${exchange}`);
  }
}

const crit = (title, page) => ({ level: 'CRITICAL', title, learnMore: link(page) });
const warn = (title, page) => ({ level: 'WARN', title, learnMore: link(page) });
const ok = (title) => ({ level: 'OK', title });

// Turn an exchange response body into findings. Pure function.
function analyze(exchange, body, status = 200) {
  const out = [];
  body = body && typeof body === 'object' ? body : {};
  if (status === 451 || status === 403) {
    return [{ level: 'ERROR', title: `${exchange} refused the request from this network (HTTP ${status}, usually a regional block). Nothing was checked. Run the check from the machine/region your bot runs in.`, learnMore: link('checker') }];
  }
  if (exchange === 'binance') {
    if (typeof body.code === 'number' && body.code < 0) return errorFindings(exchange, body.code, body.msg);
    if (typeof body.enableWithdrawals !== 'boolean') return unexpected(exchange, status);
    if (body.enableWithdrawals) out.push(crit('Withdrawals are ENABLED on this key. A trading bot never needs this.', 'permissions'));
    else out.push(ok('Withdrawals are disabled.'));
    if (body.enableInternalTransfer || body.permitsUniversalTransfer) out.push(warn('Internal/universal transfer is enabled. Turn it off unless you know you need it.', 'permissions'));
    if (!body.ipRestrict) out.push(warn('No IP whitelist. Anyone with the key can use it from anywhere.', 'checker'));
    else out.push(ok('IP whitelist is on.'));
    if (body.enableMargin) out.push(warn('Margin (borrow/repay) is enabled. Only keep it if your bot trades margin.', 'permissions'));
    return out;
  }
  if (exchange === 'bybit') {
    if (typeof body.retCode !== 'number') return unexpected(exchange, status);
    if (body.retCode !== 0) return errorFindings(exchange, body.retCode, body.retMsg);
    const r = body.result || {};
    if (!r.permissions) return unexpected(exchange, status);
    const wallet = (r.permissions && r.permissions.Wallet) || [];
    if (wallet.includes('Withdraw')) out.push(crit('Withdraw permission is ENABLED on this key. A trading bot never needs this.', 'permissions'));
    else out.push(ok('Withdraw permission is off.'));
    if (wallet.includes('AccountTransfer') || wallet.includes('SubMemberTransfer')) out.push(warn('Wallet transfer permission is enabled. Turn it off unless you need it.', 'permissions'));
    if (!r.ips || r.ips.length === 0 || r.ips.includes('*')) out.push(warn('No IP whitelist. The key can be used from anywhere and will expire.', 'bybitExpired'));
    else out.push(ok('IP whitelist is on.'));
    if (r.readOnly === 1) out.push(ok('Key is read-only.'));
    if (typeof r.deadlineDay === 'number' && r.deadlineDay >= 0 && r.deadlineDay <= 7 && (!r.ips || !r.ips.length)) out.push(warn(`Key expires in ${r.deadlineDay} day(s).`, 'bybitExpired'));
    return out;
  }
  if (exchange === 'okx') {
    if (body.code === undefined) return unexpected(exchange, status);
    if (body.code !== '0' && body.code !== 0) return errorFindings(exchange, body.code, body.msg);
    const d = (body.data && body.data[0]) || {};
    if (typeof d.perm !== 'string') return unexpected(exchange, status);
    const perm = String(d.perm || '').split(',').map((s) => s.trim());
    if (perm.includes('withdraw')) out.push(crit('Withdraw permission is ENABLED on this key. A trading bot never needs this.', 'permissions'));
    else out.push(ok('Withdraw permission is off.'));
    if (!d.ip) out.push(warn('No IP whitelist. Keys with trade permission and no IP expire after 14 days of inactivity.', 'checker'));
    else out.push(ok('IP whitelist is on.'));
    if (perm.length === 1 && perm[0] === 'read_only') out.push(ok('Key is read-only.'));
    return out;
  }
  if (exchange === 'bitget') {
    if (body.code === undefined) return unexpected(exchange, status);
    if (body.code !== '00000') return errorFindings(exchange, body.code, body.msg);
    const d = body.data || {};
    if (!Array.isArray(d.authorities) && !Array.isArray(d.permissions)) return unexpected(exchange, status);
    const auth = [].concat(d.authorities || [], d.permissions || []);
    if (auth.includes('wwow') || auth.includes('withdraw')) out.push(crit('Withdraw permission is ENABLED on this key. A trading bot never needs this.', 'permissions'));
    else out.push(ok('Withdraw permission is off.'));
    if (auth.includes('wtow')) out.push(warn('Wallet transfer (write) is enabled. Turn it off unless you need it.', 'permissions'));
    if (!d.ips) out.push(warn('No IP whitelist. Bind your server IP.', 'checker'));
    else out.push(ok('IP whitelist is on.'));
    return out;
  }
  throw new Error(`unsupported exchange: ${exchange}`);
}

function unexpected(exchange, status) {
  return [{ level: 'ERROR', title: `${exchange} returned an unexpected response (HTTP ${status}). Nothing was checked.`, learnMore: link('checker') }];
}

function errorFindings(exchange, code, msg) {
  const ex = explain(exchange, code);
  if (ex) return [{ level: 'ERROR', title: `${exchange} error ${code}: ${ex.msg}. ${ex.hint}`, learnMore: ex.learnMore }];
  // Do not echo the raw message body beyond a short, sanitized string.
  const safe = String(msg || '').replace(/[A-Za-z0-9_-]{16,}/g, '[redacted]').slice(0, 120);
  return [{ level: 'ERROR', title: `${exchange} error ${code}${safe ? `: ${safe}` : ''}`, learnMore: link('checker') }];
}

async function checkKey(exchange, { env = process.env, fetchImpl = globalThis.fetch, now = Date.now() } = {}) {
  if (!HOSTS[exchange]) throw new Error(`unsupported exchange: ${exchange} (use binance, bybit, okx or bitget)`);
  const creds = readCreds(exchange, env);
  const req = buildRequest(exchange, creds, now);
  if (!req.url.startsWith(HOSTS[exchange] + '/')) throw new Error('refusing to send credentials to a non-exchange host');
  const res = await fetchImpl(req.url, { method: 'GET', headers: req.headers, redirect: 'error' });
  let body;
  try { body = await res.json(); } catch { body = {}; }
  return analyze(exchange, body, res.status || 200);
}

module.exports = { checkKey, buildRequest, analyze, readCreds, HOSTS, PATHS, ENV };
