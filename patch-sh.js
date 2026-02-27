#!/usr/bin/env node
const fs = require('fs');
const f = '/tmp/exec-hook-merged.js';
let s = fs.readFileSync(f, 'utf-8');
const old = "cmd = command.replace(/[;&|`$(){}\\[\\]!]/g, '').trim();";
const nw = "cmd = toolName === 'sh' ? command.trim() : command.replace(/[;&|`$(){}\\[\\]!]/g, '').trim();";
if (s.includes(old)) {
  s = s.replace(old, nw);
  fs.writeFileSync(f, s);
  console.log('PATCHED: sh bypass added');
} else {
  console.log('NOT FOUND');
  const lines = s.split('\n');
  console.log('Line 254:', lines[253]);
}
