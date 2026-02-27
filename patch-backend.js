#!/usr/bin/env node
/**
 * Arsenal Backend Patch Script
 *
 * Patches the server-side analyze endpoint to:
 *  1. Only include OPEN ports (ignore filtered/closed)
 *  2. Deduplicate attacks (unique by name + host IP)
 *  3. Sort attacks by severity: critical > high > medium > low
 *
 * Usage: node patch-backend.js [path-to-server.js]
 * Default path: /data/exec-hook.js (if analyze endpoint is in the same bundle)
 *
 * If your backend is a separate file (e.g., server.js), pass that path instead.
 */

const fs = require('fs');

const targetFile = process.argv[2] || '/data/exec-hook.js';

if (!fs.existsSync(targetFile)) {
  console.error(`ERROR: File not found: ${targetFile}`);
  process.exit(1);
}

// Backup
const backupFile = targetFile + '.backend-bak.' + Date.now();
fs.copyFileSync(targetFile, backupFile);
console.log(`Backup created: ${backupFile}`);

let code = fs.readFileSync(targetFile, 'utf-8');
let patchCount = 0;

// ──────────────────────────────────────────
// PATCH 1: Filter only OPEN ports in nmap parsing
// ──────────────────────────────────────────
// Find the port regex pattern and ensure it only matches "open"
const portRegexPatterns = [
  // Pattern: matches any state (open|filtered|closed)
  /(\d+)\/(tcp|udp)\s+(\w+)\s+(\S+)/,
];

// Look for nmap parsing that doesn't filter by open
if (code.includes("'open'") || code.includes('"open"')) {
  // Check if it's already filtering
  const openFilterRegex = /state\s*===?\s*['"]open['"]/;
  if (openFilterRegex.test(code)) {
    console.log('PATCH 1: Port filtering for "open" already present');
  } else {
    console.log('PATCH 1: Found open string but no state filter — check manually');
  }
} else {
  console.log('PATCH 1: No "open" filter found — may need manual patching');
  console.log('  Ensure nmap port parsing only includes ports with state === "open"');
}

// ──────────────────────────────────────────
// PATCH 2: Deduplicate attacks
// ──────────────────────────────────────────
// Look for the attack generation loop and add dedup
if (code.includes('new Set()') && code.includes('.has(') && code.includes('.add(')) {
  console.log('PATCH 2: Deduplication via Set already present');
} else {
  // Find where attacks are pushed
  const attacksPushRegex = /attacks\.push\s*\(\s*\{/;
  const pushMatch = code.match(attacksPushRegex);
  if (pushMatch) {
    // Check if there's already a seen/dedup check above it
    const contextBefore = code.substring(Math.max(0, pushMatch.index - 500), pushMatch.index);
    if (contextBefore.includes('seen') || contextBefore.includes('dedup') || contextBefore.includes('Set()')) {
      console.log('PATCH 2: Dedup logic may already exist before attacks.push');
    } else {
      console.log('PATCH 2: attacks.push found but no dedup — add manually:');
      console.log('  const seen = new Set();');
      console.log('  // Before push: const key = `${host.ip}:${attack.name}`; if (seen.has(key)) continue; seen.add(key);');
    }
  } else {
    console.log('PATCH 2: Could not find attacks.push — manual review needed');
  }
}

// ──────────────────────────────────────────
// PATCH 3: Severity sort
// ──────────────────────────────────────────
if (code.includes('severityOrder') || code.includes('critical.*high.*medium.*low')) {
  console.log('PATCH 3: Severity ordering already present');
} else if (code.includes('attacks.sort')) {
  console.log('PATCH 3: attacks.sort found — verify it uses severity ordering');
} else {
  // Find the return/response of the attacks array
  const sortCode = `
const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
attacks.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
attacks.forEach((atk, i) => { atk.id = i + 1; });`;

  // Try to inject before the response
  const resJsonRegex = /res\.json\s*\(\s*\{[^}]*attacks/;
  const resMatch = code.match(resJsonRegex);
  if (resMatch) {
    code = code.substring(0, resMatch.index) + sortCode + '\n\n  ' + code.substring(resMatch.index);
    patchCount++;
    console.log('PATCH 3: Injected severity sort before res.json');
  } else {
    console.log('PATCH 3: Could not auto-inject sort — add manually before sending response');
    console.log(sortCode);
  }
}

// Write patched file
fs.writeFileSync(targetFile, code, 'utf-8');
console.log(`\n=== BACKEND PATCH SUMMARY ===`);
console.log(`Patches applied: ${patchCount}`);
console.log(`Backup: ${backupFile}`);
