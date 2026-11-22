'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { render } = require('../src/gitleaks');
const { fake } = require('./helpers');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', 'exchange-key-doctor.js');

test('rules/gitleaks.toml is in sync with src/rules.js', () => {
  assert.strictEqual(fs.readFileSync(path.join(ROOT, 'rules', 'gitleaks.toml'), 'utf8'), render());
});

function sample(dir) {
  fs.writeFileSync(path.join(dir, 'leak.env'), [
    `BINANCE_API_KEY=${fake.binance()}`,
    `BYBIT_API_KEY=${fake.bybitKey()}`,
    `BYBIT_API_SECRET=${fake.bybitSecret()}`,
    `OKX_API_KEY=${fake.okxKey()}`,
    `OKX_SECRET_KEY=${fake.okxSecret()}`,
    `BITGET_API_KEY=${fake.bitgetKey()}`,
    `BITGET_API_SECRET=${fake.bitgetSecret()}`,
  ].join('\n') + '\n');
  fs.writeFileSync(path.join(dir, 'clean.env'), [
    'BINANCE_API_KEY=your_binance_api_key_here',
    `RANDOM_TOKEN=${fake.binance()}`,
    'Rotate your Binance API key now.',
  ].join('\n') + '\n');
}

test('CLI scan finds all 7 in leak.env, 0 in clean.env, exit code 1, no full secret printed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ekd-'));
  sample(dir);
  const r = spawnSync(process.execPath, [BIN, 'scan', dir, '--json'], { encoding: 'utf8' });
  assert.strictEqual(r.status, 1);
  const out = JSON.parse(r.stdout);
  assert.strictEqual(out.findings.length, 7);
  assert.ok(out.findings.every((f) => f.file.endsWith('leak.env')));
  const secrets = fs.readFileSync(path.join(dir, 'leak.env'), 'utf8').split('\n').filter(Boolean).map((l) => l.split('=')[1]);
  for (const s of secrets) assert.ok(!r.stdout.includes(s), 'secret leaked to stdout');
  const clean = spawnSync(process.execPath, [BIN, 'scan', path.join(dir, 'clean.env')], { encoding: 'utf8' });
  assert.strictEqual(clean.status, 0);
  assert.match(clean.stdout, /^OK: no exchange API keys found/);
});

test('CLI explain prints the fix link', () => {
  const out = execFileSync(process.execPath, [BIN, 'explain', 'binance', '-2015'], { encoding: 'utf8' });
  assert.match(out, /https:\/\/quantaira\.app\/binance-error-2015\?utm_source=npm&utm_medium=cli&utm_campaign=exchange-key-doctor/);
});

const GITLEAKS = process.env.GITLEAKS_BIN || 'gitleaks';
const hasGitleaks = spawnSync(GITLEAKS, ['version']).status === 0;

test('gitleaks accepts the rule file and finds the same 7 (skipped if gitleaks not installed)', { skip: !hasGitleaks }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ekd-gl-'));
  sample(dir);
  const report = path.join(dir, 'report.json');
  spawnSync(GITLEAKS, ['detect', '--no-git', '--source', dir, '--config', path.join(ROOT, 'rules', 'gitleaks.toml'), '--report-format', 'json', '--report-path', report, '--no-banner'], { encoding: 'utf8' });
  const found = JSON.parse(fs.readFileSync(report, 'utf8'));
  const ours = found.filter((f) => /^(binance|bybit|okx|bitget)-/.test(f.RuleID));
  assert.strictEqual(ours.length, 7, JSON.stringify(found.map((f) => [f.RuleID, f.File])));
  assert.ok(ours.every((f) => f.File.endsWith('leak.env')));
});
