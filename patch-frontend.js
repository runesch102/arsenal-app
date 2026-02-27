#!/usr/bin/env node
/**
 * Arsenal Frontend Patch Script
 *
 * Patches exec-hook-merged.js (or /data/exec-hook.js) to:
 *  1. Add showPlan/setShowPlan useState in ArsenalExecTab
 *  2. Add attackPlan/setAttackPlan useState (if missing)
 *  3. Wire "Analysér" button to /api/arsenal/analyze
 *  4. Render AttackPlanPanel conditionally when showPlan===true
 *
 * Usage: node patch-frontend.js [path-to-exec-hook.js]
 * Default path: /data/exec-hook.js
 */

const fs = require('fs');
const path = require('path');

const targetFile = process.argv[2] || '/data/exec-hook.js';

if (!fs.existsSync(targetFile)) {
  console.error(`ERROR: File not found: ${targetFile}`);
  process.exit(1);
}

// Backup original
const backupFile = targetFile + '.bak.' + Date.now();
fs.copyFileSync(targetFile, backupFile);
console.log(`Backup created: ${backupFile}`);

let code = fs.readFileSync(targetFile, 'utf-8');
const origSize = code.length;
let patchCount = 0;

// ──────────────────────────────────────────
// PATCH 1: Add showPlan/setShowPlan useState
// ──────────────────────────────────────────
// Find ArsenalExecTab function component and its existing useState calls
// Pattern: look for "ArsenalExecTab" and existing useState near it

// Strategy A: Find "function ArsenalExecTab" or "const ArsenalExecTab"
const arsenalRegex = /(function\s+ArsenalExecTab\s*\([^)]*\)\s*\{|const\s+ArsenalExecTab\s*=\s*(?:function\s*\([^)]*\)|(?:\([^)]*\)|\w+)\s*=>)\s*\{)/;
const arsenalMatch = code.match(arsenalRegex);

if (!arsenalMatch) {
  console.error('ERROR: Could not find ArsenalExecTab component in source');
  process.exit(1);
}

console.log(`Found ArsenalExecTab at position ${arsenalMatch.index}`);

// Check if showPlan already exists
if (code.includes('showPlan') && code.includes('setShowPlan')) {
  console.log('showPlan/setShowPlan already present — skipping useState patch');
} else {
  // Find the last useState call within ArsenalExecTab (within first 2000 chars after component start)
  const componentStart = arsenalMatch.index;
  const searchWindow = code.substring(componentStart, componentStart + 3000);

  // Find all useState calls in this window
  const useStatePattern = /(?:const|let|var)\s+\[(\w+),\s*(\w+)\]\s*=\s*(?:React\.)?useState\([^)]*\)\s*;?/g;
  let lastUseStateMatch = null;
  let match;
  while ((match = useStatePattern.exec(searchWindow)) !== null) {
    lastUseStateMatch = match;
  }

  if (lastUseStateMatch) {
    const insertPos = componentStart + lastUseStateMatch.index + lastUseStateMatch[0].length;
    const injection = `\n  const [showPlan, setShowPlan] = useState(false);\n  const [attackPlan, setAttackPlan] = useState(null);`;

    // Check if attackPlan already exists
    const hasAttackPlan = searchWindow.includes('attackPlan');
    const injectCode = hasAttackPlan
      ? `\n  const [showPlan, setShowPlan] = useState(false);`
      : injection;

    code = code.substring(0, insertPos) + injectCode + code.substring(insertPos);
    patchCount++;
    console.log(`PATCH 1: Injected showPlan/setShowPlan useState after existing useState declarations`);
  } else {
    // Fallback: inject right after the opening brace of ArsenalExecTab
    const bracePos = code.indexOf('{', arsenalMatch.index) + 1;
    const injection = `\n  const [showPlan, setShowPlan] = useState(false);\n  const [attackPlan, setAttackPlan] = useState(null);`;
    code = code.substring(0, bracePos) + injection + code.substring(bracePos);
    patchCount++;
    console.log(`PATCH 1 (fallback): Injected useState at ArsenalExecTab opening`);
  }
}

// ──────────────────────────────────────────
// PATCH 2: Wire "Analysér" button handler
// ──────────────────────────────────────────
// Look for the analyze/submit handler in ArsenalExecTab
if (code.includes('handleAnalyze') || code.includes('/api/arsenal/analyze')) {
  console.log('handleAnalyze or /api/arsenal/analyze already present — checking for showPlan wiring');

  // Ensure setShowPlan(true) is called in the success handler
  if (!code.includes('setShowPlan(true)') && !code.includes('setShowPlan( true )')) {
    // Find where attackPlan is set in the response handler
    const setAttackPlanRegex = /setAttackPlan\s*\(\s*(?:data|result|response|res\.data|json)\s*\)/;
    const setAttackPlanMatch = code.match(setAttackPlanRegex);
    if (setAttackPlanMatch) {
      const insertPos = setAttackPlanMatch.index + setAttackPlanMatch[0].length;
      code = code.substring(0, insertPos) + ';\n      setShowPlan(true)' + code.substring(insertPos);
      patchCount++;
      console.log('PATCH 2a: Added setShowPlan(true) after setAttackPlan()');
    }
  }
} else {
  // Need to inject the full analyze handler
  // Find "Analysér" button or similar
  const analyzeHandlerCode = `
  const handleAnalyze = async () => {
    if (!target || !target.trim()) return;
    setShowPlan(false);
    setAttackPlan(null);
    try {
      const res = await fetch('/api/arsenal/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim() })
      });
      if (!res.ok) throw new Error('Server responded ' + res.status);
      const data = await res.json();
      setAttackPlan(data);
      setShowPlan(true);
    } catch (err) {
      console.error('Analyze failed:', err);
    }
  };`;

  // Insert before the return statement of ArsenalExecTab
  const componentStart2 = code.indexOf('ArsenalExecTab');
  const returnMatch = code.indexOf('return', componentStart2 + 100);
  if (returnMatch > componentStart2) {
    code = code.substring(0, returnMatch) + analyzeHandlerCode + '\n\n  ' + code.substring(returnMatch);
    patchCount++;
    console.log('PATCH 2: Injected full handleAnalyze function');
  }
}

// ──────────────────────────────────────────
// PATCH 3: Conditional rendering of AttackPlanPanel
// ──────────────────────────────────────────
if (code.includes('showPlan') && code.includes('AttackPlanPanel')) {
  // Check if already conditionally rendered
  if (code.includes('showPlan && ') || code.includes('showPlan&&')) {
    console.log('PATCH 3: AttackPlanPanel already conditionally rendered with showPlan');
  } else {
    // Find <AttackPlanPanel and wrap it
    const panelRegex = /(<AttackPlanPanel\b)/;
    const panelMatch = code.match(panelRegex);
    if (panelMatch) {
      code = code.replace(panelRegex, '{showPlan && $1');
      // Find the closing of AttackPlanPanel
      const closeRegex = /(<\/AttackPlanPanel\s*>|<AttackPlanPanel[^/]*\/>)/;
      const closeMatch = code.match(closeRegex);
      if (closeMatch) {
        code = code.replace(closeRegex, '$1}');
      }
      patchCount++;
      console.log('PATCH 3: Wrapped AttackPlanPanel in {showPlan && ...}');
    }
  }
} else if (!code.includes('AttackPlanPanel')) {
  // AttackPlanPanel component doesn't exist — inject it
  // Find end of ArsenalExecTab return JSX to inject the panel
  console.log('PATCH 3: AttackPlanPanel not found — user may need to add it manually');
  console.log('  Suggested JSX: {showPlan && attackPlan && <AttackPlanPanel attackPlan={attackPlan} />}');
}

// ──────────────────────────────────────────
// Write patched file
// ──────────────────────────────────────────
fs.writeFileSync(targetFile, code, 'utf-8');
const newSize = code.length;

console.log(`\n=== PATCH SUMMARY ===`);
console.log(`Original size: ${origSize} bytes`);
console.log(`Patched size:  ${newSize} bytes`);
console.log(`Patches applied: ${patchCount}`);
console.log(`Backup: ${backupFile}`);
console.log(`\nTo verify: grep -c showPlan ${targetFile}`);
