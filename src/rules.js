'use strict';
// Detection rules for crypto exchange API credentials.
// Design goal: LOW false positives. Most exchange keys have no prefix, so a value
// only counts when (a) it has the exact shape the exchange issues, (b) it is
// assigned to a key/secret-like name, and (c) the exchange name appears on the
// same line or within CONTEXT_LINES lines above (covers ccxt-style config blocks).
// Bitget API keys carry a "bg_" prefix, so that one rule needs no context.

const CONTEXT_LINES = 4;

// name = value | "name": "value" | name: 'value' | name=value
// Value must be bounded by quotes/whitespace/end so longer tokens don't match.
function assignment(namePattern, valuePattern) {
  return new RegExp(
    `(?:^|[^A-Za-z0-9])(${namePattern})["'\`]?\\s*(?::|=|=>|:=)\\s*["'\`]?(${valuePattern})(?=$|["'\`\\s,;)}\\]#])`,
    'i'
  );
}

const KEY_NAME = '[A-Za-z0-9_.-]{0,30}?(?:api[_.-]?key|apikey|access[_.-]?key|key)';
const SECRET_NAME = '[A-Za-z0-9_.-]{0,30}?(?:secret|api[_.-]?secret|secret[_.-]?key|private[_.-]?key)';

const RULES = [
  {
    id: 'binance-api-credential',
    exchange: 'binance',
    title: 'Binance API key or secret',
    context: /binance/i,
    // Binance HMAC API keys and secrets are 64 alphanumeric characters.
    pattern: assignment(`${KEY_NAME}|${SECRET_NAME}`, '[A-Za-z0-9]{64}'),
    minEntropy: 4.0,
    gitleaks: {
      regex: `(?i)binance[\\w.-]{0,20}(?:api[_.-]?key|apikey|key|secret|secret[_.-]?key|api[_.-]?secret)["'\`]?\\s*(?::|=|=>|:=)\\s*["'\`]?([A-Za-z0-9]{64})(?:$|["'\`\\s,;)}\\]#])`,
      keywords: ['binance'],
      entropy: 4.0,
    },
  },
  {
    id: 'bybit-api-key',
    exchange: 'bybit',
    title: 'Bybit API key',
    context: /bybit/i,
    // Bybit system-generated API keys are 18 alphanumeric characters.
    pattern: assignment(KEY_NAME, '[A-Za-z0-9]{18}'),
    minEntropy: 3.2,
    gitleaks: {
      regex: `(?i)bybit[\\w.-]{0,20}(?:api[_.-]?key|apikey|key)["'\`]?\\s*(?::|=|=>|:=)\\s*["'\`]?([A-Za-z0-9]{18})(?:$|["'\`\\s,;)}\\]#])`,
      keywords: ['bybit'],
      entropy: 3.2,
    },
  },
  {
    id: 'bybit-api-secret',
    exchange: 'bybit',
    title: 'Bybit API secret',
    context: /bybit/i,
    // Bybit HMAC secrets are 36 alphanumeric characters.
    pattern: assignment(SECRET_NAME, '[A-Za-z0-9]{36}'),
    minEntropy: 3.6,
    gitleaks: {
      regex: `(?i)bybit[\\w.-]{0,20}(?:secret|api[_.-]?secret|secret[_.-]?key)["'\`]?\\s*(?::|=|=>|:=)\\s*["'\`]?([A-Za-z0-9]{36})(?:$|["'\`\\s,;)}\\]#])`,
      keywords: ['bybit'],
      entropy: 3.6,
    },
  },
  {
    id: 'okx-api-key',
    exchange: 'okx',
    title: 'OKX API key',
    context: /okx|okex/i,
    // OKX API keys are UUIDs.
    pattern: assignment(KEY_NAME, '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    minEntropy: 3.0,
    gitleaks: {
      regex: `(?i)ok(?:x|ex)[\\w.-]{0,20}(?:api[_.-]?key|apikey|access[_.-]?key|key)["'\`]?\\s*(?::|=|=>|:=)\\s*["'\`]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:$|["'\`\\s,;)}\\]#])`,
      keywords: ['okx', 'okex'],
      entropy: 3.0,
    },
  },
  {
    id: 'okx-api-secret',
    exchange: 'okx',
    title: 'OKX API secret',
    context: /okx|okex/i,
    // OKX secrets are 32 uppercase hex characters.
    pattern: assignment(SECRET_NAME, '[0-9A-F]{32}'),
    caseSensitiveValue: /^[0-9A-F]{32}$/,
    minEntropy: 3.2,
    gitleaks: {
      regex: `(?i)ok(?:x|ex)[\\w.-]{0,20}(?:secret|api[_.-]?secret|secret[_.-]?key)["'\`]?\\s*(?::|=|=>|:=)\\s*["'\`]?([0-9A-Fa-f]{32})(?:$|["'\`\\s,;)}\\]#])`,
      keywords: ['okx', 'okex'],
      entropy: 3.2,
    },
  },
  {
    id: 'bitget-api-key',
    exchange: 'bitget',
    title: 'Bitget API key (bg_ prefix)',
    context: null, // the bg_ prefix is distinctive enough
    pattern: /(?:^|[^A-Za-z0-9_])(bg_)([0-9a-f]{32})(?![0-9A-Za-z])/,
    valueGroup: 2,
    minEntropy: 3.0,
    gitleaks: {
      regex: `(?:^|[^A-Za-z0-9_])(bg_[0-9a-f]{32})(?:$|[^0-9A-Za-z])`,
      keywords: ['bg_'],
      entropy: 3.0,
    },
  },
  {
    id: 'bitget-api-secret',
    exchange: 'bitget',
    title: 'Bitget API secret',
    context: /bitget/i,
    // Bitget HMAC secrets are 64 lowercase hex characters.
    pattern: assignment(SECRET_NAME, '[0-9a-f]{64}'),
    caseSensitiveValue: /^[0-9a-f]{64}$/,
    minEntropy: 3.5,
    gitleaks: {
      regex: `(?i)bitget[\\w.-]{0,20}(?:secret|api[_.-]?secret|secret[_.-]?key)["'\`]?\\s*(?::|=|=>|:=)\\s*["'\`]?([0-9a-f]{64})(?:$|["'\`\\s,;)}\\]#])`,
      keywords: ['bitget'],
      entropy: 3.5,
    },
  },
];

// Values that are obviously examples. Matching is case-insensitive.
const STOPWORDS = ['example', 'sample', 'dummy', 'placeholder', 'changeme', 'your', 'xxxx', 'test', 'fake', 'redacted', 'abcdef0123', '0123456789'];

module.exports = { RULES, STOPWORDS, CONTEXT_LINES };
