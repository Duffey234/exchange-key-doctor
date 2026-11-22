# exchange-key-doctor

Find leaked crypto exchange API keys in your code, check whether your own key can withdraw funds, and get a plain explanation of exchange API-key errors. Covers **Binance, Bybit, OKX and Bitget**. Ships a ready-made **gitleaks** rule file, because gitleaks' default rules have no Binance, Bybit, OKX or Bitget patterns.

[npm](https://www.npmjs.com/package/exchange-key-doctor) · [GitHub](https://github.com/Duffey234/exchange-key-doctor) · agent skill: [exchange-key-safety](https://github.com/Duffey234/exchange-key-safety-skill)

We built this at YourAITools, along with the free guides it links to on [quantaira.app](https://quantaira.app/api-key-safety-checker?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor). It's education and hygiene tooling, not a security audit or financial advice.

```bash
npx exchange-key-doctor scan .                 # find exchange keys in files
npx exchange-key-doctor scan --staged          # pre-commit: only staged files
npx exchange-key-doctor check binance          # opt-in: what can MY key do? (read-only)
npx exchange-key-doctor explain bybit 10003    # what does this error mean?
npx exchange-key-doctor gitleaks > exchange-keys.gitleaks.toml
```

## 1. Scan for leaked keys

Most exchange keys have no prefix, so a bare 64-character string could be anything. To keep false positives low, a value only counts when all of these hold:

- it has the exact shape that exchange issues:
  - Binance: 64 alphanumeric characters
  - Bybit: an 18-character key or a 36-character secret
  - OKX: a UUID key or a 32-character uppercase hex secret
  - Bitget: a `bg_` + 32 hex key or a 64-character hex secret
- it is assigned to a key/secret-style name (`BINANCE_API_KEY=`, `apiKey:`, `"secret": `)
- the exchange name appears on the same line, within 4 lines above (ccxt-style config blocks), or in the file name (`binance.env`)
- it is not an obvious placeholder (`your_key`, `xxxx`, repeated or sequential characters), and its randomness (entropy) is high enough

Bitget API keys start with `bg_`, so that rule needs no extra context.

Findings are **redacted** (`AbCd********yz (64 chars)`) and the full value is never printed. The command exits with code `1` when something is found, so it works in CI and in pre-commit hooks. Add `exchange-key-doctor:allow` (or `gitleaks:allow`) to a line to skip it.

We tested it on the published npm packages of ccxt, binance, bybit-api, okx-api and bitget-api (83 MB, 1,176 text files). It flagged 3 lines, all the same 64-character example key in a commented-out docs snippet. The gitleaks rule file flagged 0.

**If it finds a real key:** delete the key on the exchange first (assume it was copied), then create a new trade-only key with withdrawals off and an IP whitelist. See [what to do after a key leak](https://quantaira.app/api-key-leak-tracker?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor).

### Pre-commit hook (plain git)

```bash
printf '#!/bin/sh\nnpx --no-install exchange-key-doctor scan --staged\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### gitleaks

```bash
gitleaks detect --config node_modules/exchange-key-doctor/rules/gitleaks.toml
```

The file uses `[extend] useDefault = true`, so you keep all the default gitleaks rules. The gitleaks rules are stricter than the CLI: the exchange name has to be part of the variable name on the same line.

## 2. Check what your key can do (opt-in, read-only)

`check` asks the exchange's own "API key info" endpoint what the key you already use is allowed to do:

| Exchange | Endpoint (GET, read-only) | Env vars |
| --- | --- | --- |
| Binance | `api.binance.com/sapi/v1/account/apiRestrictions` | `BINANCE_API_KEY`, `BINANCE_API_SECRET` |
| Bybit | `api.bybit.com/v5/user/query-api` | `BYBIT_API_KEY`, `BYBIT_API_SECRET` |
| OKX | `www.okx.com/api/v5/account/config` | `OKX_API_KEY`, `OKX_API_SECRET`, `OKX_API_PASSPHRASE` |
| Bitget | `api.bitget.com/api/v2/spot/account/info` | `BITGET_API_KEY`, `BITGET_API_SECRET`, `BITGET_API_PASSPHRASE` |

It reports:
- **CRITICAL** if withdrawals are enabled (a trading bot never needs that)
- **WARN** for wallet/universal transfer, a missing IP whitelist, margin, or a key that expires soon
- **OK** for safe settings

How it treats your credentials:
- It reads them **from environment variables only**. There are no flags, so they don't end up in your shell history.
- It sends them **only** to the host in the table above. The URL is checked before sending, and redirects are refused.
- It **never prints, logs or stores** them, or the raw response. Unknown error messages are shortened and long tokens are removed.
- There's no telemetry and no other network calls. Read `src/check.js` (about 160 lines).

Some exchanges block certain countries (for example, HTTP 451 from Binance or 403 from Bybit). In that case you get an ERROR saying nothing was checked, never a false "OK". Run the check from where your bot runs.

The guide on [what permissions a trading bot key needs](https://quantaira.app/trading-bot-api-key-permissions?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor) explains each setting.

## 3. Explain an error

```
$ npx exchange-key-doctor explain binance -2015
binance -2015: Invalid API-key, IP, or permissions for action
  Check the IP whitelist, that the key has the permission this call needs, and that you are not mixing testnet and live keys.
  Full fix: https://quantaira.app/binance-error-2015?...
```

Known codes:

| Exchange | Codes | Fix guide |
| --- | --- | --- |
| Binance | -2015, -2014, -1022 | [Binance -2015 fix guide](https://quantaira.app/binance-error-2015?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor) |
| Bybit | 10003, 10004, 10010 | [Bybit 10003 fix guide](https://quantaira.app/bybit-error-10003?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor) |
| Bybit | 33004 | [Bybit expired key guide](https://quantaira.app/bybit-api-key-expired?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor) |
| OKX | 50119, 50111, 50113, 50105 | [OKX 50119 fix guide](https://quantaira.app/okx-api-key-doesnt-exist?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor) |
| Bitget | 40012 | [forgot your Bitget passphrase](https://quantaira.app/bitget-forgot-api-passphrase?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor) |
| Bitget | 40006, 40037, 40009 | [key safety checklist](https://quantaira.app/api-key-safety-checker?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor) |

## Library use

```js
const { scanText, analyze, explain } = require('exchange-key-doctor');
scanText(fileContents, 'config.js'); // => [{ rule, exchange, file, line, preview, learnMore, ... }]
```

## More free guides

- [API key safety checklist](https://quantaira.app/api-key-safety-checker?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor)
- [Is it safe to give an API key to Claude or an AI agent?](https://quantaira.app/is-it-safe-to-give-api-key-to-claude?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor)
- [Trading bot scam red flags](https://quantaira.app/crypto-trading-bot-scam-red-flags?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor)
- [3Commas API key leak (2022)](https://quantaira.app/3commas-api-key-leak?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor)

## License

MIT. No warranty. Patterns are based on public exchange docs. Exchanges can change key formats, so a clean scan is not proof that no secrets are present.
