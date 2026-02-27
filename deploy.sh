#!/bin/bash
# ============================================================
# Arsenal Fix — Deploy Script
# Run this ON the remote server (152.53.154.171)
# ============================================================
set -e

EXEC_HOOK="/data/exec-hook.js"
BACKUP="${EXEC_HOOK}.bak.$(date +%s)"

echo "=== Arsenal Deployment Script ==="
echo ""

# 1. Backup
if [ -f "$EXEC_HOOK" ]; then
  cp "$EXEC_HOOK" "$BACKUP"
  echo "[OK] Backup: $BACKUP"
else
  echo "[WARN] $EXEC_HOOK not found — checking alternatives..."
  # Try common locations
  for f in ./exec-hook-merged.js ./exec-hook.js /app/exec-hook.js; do
    if [ -f "$f" ]; then
      EXEC_HOOK="$f"
      cp "$EXEC_HOOK" "${EXEC_HOOK}.bak.$(date +%s)"
      echo "[OK] Found: $EXEC_HOOK"
      break
    fi
  done
fi

if [ ! -f "$EXEC_HOOK" ]; then
  echo "[ERROR] Cannot find exec-hook.js"
  exit 1
fi

echo ""
echo "File: $EXEC_HOOK ($(wc -c < "$EXEC_HOOK") bytes)"

# 2. Patch frontend: Add showPlan/setShowPlan useState
echo ""
echo "--- PATCH 1: Add showPlan/setShowPlan useState ---"

# Check if already patched
if grep -q "showPlan" "$EXEC_HOOK"; then
  echo "[SKIP] showPlan already exists in file"
else
  # Find the last useState in ArsenalExecTab and inject after it
  # This sed finds "ArsenalExecTab" block's last useState and adds showPlan after it
  node -e "
    const fs = require('fs');
    let code = fs.readFileSync('$EXEC_HOOK', 'utf-8');

    // Find ArsenalExecTab
    const idx = code.indexOf('ArsenalExecTab');
    if (idx === -1) { console.log('[ERROR] ArsenalExecTab not found'); process.exit(1); }

    // Search for useState calls after ArsenalExecTab (within 3000 chars)
    const window = code.substring(idx, idx + 3000);
    const re = /useState\([^)]*\)\s*;?/g;
    let last = null, m;
    while ((m = re.exec(window)) !== null) last = m;

    if (!last) { console.log('[ERROR] No useState found in ArsenalExecTab'); process.exit(1); }

    const insertAt = idx + last.index + last[0].length;
    const hasAttackPlan = window.includes('attackPlan');
    const inject = hasAttackPlan
      ? '\n  const [showPlan, setShowPlan] = useState(false);'
      : '\n  const [showPlan, setShowPlan] = useState(false);\n  const [attackPlan, setAttackPlan] = useState(null);';

    code = code.slice(0, insertAt) + inject + code.slice(insertAt);
    fs.writeFileSync('$EXEC_HOOK', code);
    console.log('[OK] Injected showPlan useState');
  "
fi

# 3. Patch: Wire Analysér button to fetch /api/arsenal/analyze
echo ""
echo "--- PATCH 2: Wire analyze handler with setShowPlan(true) ---"

if grep -q "setShowPlan(true)" "$EXEC_HOOK"; then
  echo "[SKIP] setShowPlan(true) already present"
else
  node -e "
    const fs = require('fs');
    let code = fs.readFileSync('$EXEC_HOOK', 'utf-8');

    // Find setAttackPlan(data) or similar and add setShowPlan(true) after it
    const patterns = [
      /setAttackPlan\s*\(\s*\w+\s*\)/,
      /setAttackPlan\s*\(\s*data\s*\)/,
      /setAttackPlan\s*\(\s*result\s*\)/,
      /setAttackPlan\s*\(\s*response\s*\)/,
    ];

    let found = false;
    for (const pat of patterns) {
      const m = code.match(pat);
      if (m) {
        const pos = m.index + m[0].length;
        code = code.slice(0, pos) + ';\n      setShowPlan(true)' + code.slice(pos);
        found = true;
        break;
      }
    }

    if (!found) {
      // Try to find the fetch success handler and inject both calls
      const fetchIdx = code.indexOf('/api/arsenal/analyze');
      if (fetchIdx > -1) {
        // Find .then after fetch
        const thenIdx = code.indexOf('.then', fetchIdx);
        if (thenIdx > -1) {
          console.log('[WARN] Found fetch but could not auto-wire setShowPlan — manual edit needed');
          process.exit(0);
        }
      }
      console.log('[WARN] Could not find setAttackPlan call — manual edit may be needed');
      process.exit(0);
    }

    fs.writeFileSync('$EXEC_HOOK', code);
    console.log('[OK] Added setShowPlan(true) after setAttackPlan');
  "
fi

# 4. Patch: Conditional rendering of AttackPlanPanel
echo ""
echo "--- PATCH 3: Conditional render {showPlan && <AttackPlanPanel>} ---"

if grep -q "showPlan.*AttackPlanPanel\|showPlan &&" "$EXEC_HOOK"; then
  echo "[SKIP] Conditional rendering already present"
else
  node -e "
    const fs = require('fs');
    let code = fs.readFileSync('$EXEC_HOOK', 'utf-8');

    // Find <AttackPlanPanel and wrap with {showPlan &&
    const panelIdx = code.indexOf('AttackPlanPanel');
    if (panelIdx === -1) {
      console.log('[WARN] AttackPlanPanel not found in source');
      process.exit(0);
    }

    // Find the JSX opening: look backwards from AttackPlanPanel for '<' or '{'
    let openIdx = panelIdx;
    while (openIdx > 0 && code[openIdx] !== '<') openIdx--;

    // Check if already wrapped
    const before = code.substring(Math.max(0, openIdx - 20), openIdx).trim();
    if (before.endsWith('&&') || before.includes('showPlan')) {
      console.log('[SKIP] Already wrapped');
      process.exit(0);
    }

    // Wrap: insert {showPlan && before <AttackPlanPanel
    code = code.slice(0, openIdx) + '{showPlan && ' + code.slice(openIdx);

    // Find closing /> or </AttackPlanPanel>
    let closeIdx = code.indexOf('/>', openIdx + 20);
    const closeTag = code.indexOf('</AttackPlanPanel>', openIdx + 20);
    if (closeTag > -1 && (closeTag < closeIdx || closeIdx === -1)) {
      closeIdx = closeTag + '</AttackPlanPanel>'.length;
    } else if (closeIdx > -1) {
      closeIdx += 2; // skip />
    }

    if (closeIdx > -1) {
      code = code.slice(0, closeIdx) + '}' + code.slice(closeIdx);
    }

    fs.writeFileSync('$EXEC_HOOK', code);
    console.log('[OK] Wrapped AttackPlanPanel in {showPlan && ...}');
  "
fi

# 5. Verify
echo ""
echo "=== VERIFICATION ==="
SHOW_PLAN_COUNT=$(grep -c "showPlan" "$EXEC_HOOK" || echo "0")
echo "showPlan occurrences: $SHOW_PLAN_COUNT"
echo "File size: $(wc -c < "$EXEC_HOOK") bytes"

if [ "$SHOW_PLAN_COUNT" -gt "0" ]; then
  echo ""
  echo "[SUCCESS] Frontend patched successfully!"
  echo ""
  echo "Next steps:"
  echo "  1. Restart service: pm2 restart all  OR  systemctl restart arsenal"
  echo "  2. Verify: curl http://152.53.154.171:3000/ | grep -c showPlan"
else
  echo "[FAIL] showPlan not found after patching"
  echo "Restoring backup..."
  cp "$BACKUP" "$EXEC_HOOK"
fi
