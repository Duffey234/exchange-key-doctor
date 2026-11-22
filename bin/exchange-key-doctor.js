#!/usr/bin/env node
'use strict';
const { execFileSync } = require('node:child_process');
const { scanPaths } = require('../src/scan');
const { checkKey, ENV } = require('../src/check');
const { explain, CODES } = require('../src/explain');
const { link } = require('../src/links');
const pkg = require('../package.json');

const HELP = `exchange-key-doctor ${pkg.version}
Find leaked crypto exchange API keys and risky key permissions (Binance, Bybit, OKX, Bitget).

Usage:
  exchange-key-doctor scan [paths...]      Scan files/folders (default: .) for exchange keys
  exchange-key-doctor scan --staged        Scan only files staged in git (use as a pre-commit hook)
  exchange-key-doctor check <exchange>     Opt-in: ask the exchange what YOUR key can do (read-only)
  exchange-key-doctor explain <exchange> <code>   Explain an exchange API error code
  exchange-key-doctor gitleaks             Print the gitleaks rule file

Options:
  --json        Machine-readable output
  --no-links    Do not print guide links
  -h, --help    Show help

check reads credentials from environment variables only:
${Object.entries(ENV).map(([ex, v]) => `  ${ex.padEnd(8)} ${v.join(', ')}`).join('\n')}
They are sent only to that exchange's own read-only key-info endpoint and are never printed or stored.

Guide: ${link('checker')}`;

function print(json, data, human) {
  if (json) process.stdout.write(JSON.stringify(data, null, 2) + '\n');
  else human();
}

async function main(argv) {
  const args = argv.slice(2);
  const json = args.includes('--json');
  const links = !args.includes('--no-links');
  const FLAGS = new Set(['--json', '--no-links', '--staged', '-h', '--help']);
  const pos = args.filter((a) => !FLAGS.has(a));
  const cmd = pos.shift();
  if (!cmd || args.includes('-h') || args.includes('--help')) { console.log(HELP); return 0; }

  if (cmd === 'scan') {
    let targets = pos.length ? pos : ['.'];
    if (args.includes('--staged')) {
      const out = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACM'], { encoding: 'utf8' });
      targets = out.split('\n').filter(Boolean);
    }
    const { files, findings } = scanPaths(targets);
    print(json, { files, findings }, () => {
      if (!findings.length) { console.log(`OK: no exchange API keys found in ${files} file(s).`); return; }
      console.log(`Found ${findings.length} possible exchange API credential(s) in ${files} file(s):\n`);
      for (const f of findings) {
        console.log(`  ${f.file}:${f.line}  ${f.title}  ${f.preview}`);
      }
      console.log(`\nWhat to do: ${findings[0].fix}`);
      if (links) {
        console.log(`  Safe key settings: ${link('permissions')}`);
        console.log(`  Leaked-key response steps: ${link('leakTracker')}`);
      }
    });
    return findings.length ? 1 : 0;
  }

  if (cmd === 'check') {
    const exchange = (pos[0] || '').toLowerCase();
    try {
      const results = await checkKey(exchange);
      print(json, { exchange, results }, () => {
        console.log(`${exchange} key check (read-only):\n`);
        for (const r of results) {
          console.log(`  [${r.level}] ${r.title}`);
          if (links && r.learnMore) console.log(`          ${r.learnMore}`);
        }
      });
      return results.some((r) => r.level === 'CRITICAL' || r.level === 'ERROR') ? 1 : 0;
    } catch (e) {
      // Never include credentials in error output.
      console.error(`check failed: ${e.code === 'MISSING_ENV' ? e.message : String(e.message).slice(0, 160)}`);
      return 2;
    }
  }

  if (cmd === 'explain') {
    const [exchange, code] = pos;
    const ex = explain(exchange, code);
    if (!ex) {
      console.error(`unknown code. Known: ${Object.entries(CODES).map(([k, v]) => `${k} ${Object.keys(v).join('/')}`).join('; ')}`);
      return 2;
    }
    print(json, ex, () => {
      console.log(`${ex.exchange} ${ex.code}: ${ex.msg}\n  ${ex.hint}`);
      if (links) console.log(`  Full fix: ${ex.learnMore}`);
    });
    return 0;
  }

  if (cmd === 'gitleaks') { process.stdout.write(require('../src/gitleaks').render()); return 0; }

  console.error(`unknown command: ${cmd}\n\n${HELP}`);
  return 2;
}

main(process.argv).then((code) => { process.exitCode = code; });
