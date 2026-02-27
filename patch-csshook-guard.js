#!/usr/bin/env node
// Prevent css-hook.js from injecting OLD InjectionPanel when
// FRONTEND_GZ_B64 already has the NEW one with handleInject
const fs = require('fs');
const f = '/data/css-hook.js';
if (!fs.existsSync(f)) { console.log('NOT FOUND:', f); process.exit(1); }
let s = fs.readFileSync(f, 'utf-8');

// The old guard:  if(injIdx >= 0){
// New guard: also check that handleInject doesn't already exist
const oldGuard = "if(injIdx >= 0){\n    h = h.substring(0, injIdx) + injPanelCode + h.substring(injIdx);";
const newGuard = "if(injIdx >= 0 && !h.includes('handleInject')){\n    h = h.substring(0, injIdx) + injPanelCode + h.substring(injIdx);";

if (s.includes('handleInject')) {
  console.log('ALREADY PATCHED');
} else if (s.includes(oldGuard)) {
  s = s.replace(oldGuard, newGuard);
  fs.writeFileSync(f, s);
  console.log('PATCHED: Added handleInject guard to css-hook.js');
} else {
  console.log('WARN: Could not find exact guard pattern');
  // Try a more flexible match
  const altOld = "if(injIdx >= 0){";
  // Find the one that's near InjectionPanel
  const injPanelPos = s.indexOf('injPanelCode');
  if (injPanelPos >= 0) {
    const guardPos = s.indexOf(altOld, injPanelPos);
    if (guardPos >= 0 && guardPos - injPanelPos < 1000) {
      s = s.substring(0, guardPos) + "if(injIdx >= 0 && !h.includes('handleInject')){" + s.substring(guardPos + altOld.length);
      fs.writeFileSync(f, s);
      console.log('PATCHED (alt): Added handleInject guard');
    } else {
      console.log('ERROR: Guard not found near injPanelCode');
    }
  }
}
