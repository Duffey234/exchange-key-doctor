'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { RULES, STOPWORDS, CONTEXT_LINES } = require('./rules');
const { shannon } = require('./entropy');
const { link } = require('./links');

const SKIP_DIRS = new Set(['.git', 'node_modules', '.hg', '.svn', 'dist', 'build', 'coverage', '.venv', 'venv', '__pycache__', '.next', '.cache']);
const MAX_BYTES = 2 * 1024 * 1024;

function redact(value) {
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}${'*'.repeat(8)}${value.slice(-2)} (${value.length} chars)`;
}

function isPlaceholder(value) {
  const v = value.toLowerCase();
  if (STOPWORDS.some((w) => v.includes(w))) return true;
  if (/^(.)\1+$/.test(v)) return true; // aaaa / 0000
  if (/^(.{1,4})\1{3,}$/.test(v)) return true; // repeated short block
  // alphabet / digit runs: abcdefghij..., 123456789...
  let run = 1;
  for (let i = 1; i < v.length; i++) {
    run = v.charCodeAt(i) === v.charCodeAt(i - 1) + 1 ? run + 1 : 1;
    if (run >= 8) return true;
  }
  return false;
}

function hasContext(rule, lines, idx, filePath) {
  if (!rule.context) return true;
  if (rule.context.test(path.basename(filePath))) return true;
  for (let i = Math.max(0, idx - CONTEXT_LINES); i <= idx; i++) {
    if (rule.context.test(lines[i])) return true;
  }
  return false;
}

function findingFor(rule) {
  if (rule.exchange === 'binance') return link('permissions');
  return link('checker');
}

// Scan one text buffer. Returns findings (values are redacted; raw values never leave this function).
function scanText(text, filePath = '<input>') {
  const findings = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 5000) continue; // minified blobs
    if (/exchange-key-doctor:allow|gitleaks:allow/.test(line)) continue; // inline opt-out
    for (const rule of RULES) {
      const m = rule.pattern.exec(line);
      if (!m) continue;
      const value = m[rule.valueGroup || 2];
      if (!value) continue;
      if (rule.caseSensitiveValue && !rule.caseSensitiveValue.test(value)) continue;
      if (isPlaceholder(value)) continue;
      if (shannon(value) < rule.minEntropy) continue;
      if (!hasContext(rule, lines, i, filePath)) continue;
      const full = rule.id === 'bitget-api-key' ? `bg_${value}` : value;
      findings.push({
        rule: rule.id,
        exchange: rule.exchange,
        title: rule.title,
        file: filePath,
        line: i + 1,
        preview: redact(full),
        fix: 'Delete this key on the exchange now (it may already be copied), create a new trade-only key with withdrawals OFF and an IP whitelist, and load it from an environment variable or secret manager.',
        learnMore: findingFor(rule),
        leakResponse: link('leakTracker'),
      });
    }
  }
  return findings;
}

function looksBinary(buf) {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

function* walk(target) {
  let st;
  try { st = fs.lstatSync(target); } catch { return; }
  if (st.isSymbolicLink()) return;
  if (st.isFile()) { yield target; return; }
  if (!st.isDirectory()) return;
  for (const entry of fs.readdirSync(target)) {
    if (SKIP_DIRS.has(entry)) continue;
    yield* walk(path.join(target, entry));
  }
}

function scanPaths(targets) {
  const findings = [];
  let files = 0;
  for (const t of targets) {
    for (const file of walk(t)) {
      let buf;
      try {
        const st = fs.statSync(file);
        if (st.size > MAX_BYTES) continue;
        buf = fs.readFileSync(file);
      } catch { continue; }
      if (looksBinary(buf)) continue;
      files++;
      findings.push(...scanText(buf.toString('utf8'), file));
    }
  }
  return { files, findings };
}

module.exports = { scanText, scanPaths, isPlaceholder, redact };
