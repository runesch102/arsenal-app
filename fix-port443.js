// fix-port443.js - Remove PORT_443_LISTENER block from server.js
const fs = require('fs');
const FILE = '/data/server-v4.3.js';

try {
  let s = fs.readFileSync(FILE, 'utf8');
  console.log('[FIX] File size:', s.length);
  
  if (!s.includes('PORT_443_LISTENER')) {
    console.log('[FIX] No PORT_443_LISTENER found - file is clean');
    process.exit(0);
  }
  
  // Find the start: the comment line
  let start = s.indexOf('// PORT_443_LISTENER');
  // Go back to include the empty line before it
  start = s.lastIndexOf('\n', start);
  
  // Find the end: after https443.listen(...) and the closing }
  let end = s.indexOf('https443.listen(', start);
  if (end < 0) {
    console.log('[FIX] WARNING: PORT_443_LISTENER marker found but no https443.listen - trying alternate removal');
    // Just remove the comment line
    let lineEnd = s.indexOf('\n', s.indexOf('PORT_443_LISTENER'));
    s = s.substring(0, start) + s.substring(lineEnd);
    fs.writeFileSync(FILE, s);
    console.log('[FIX] Removed PORT_443_LISTENER comment line. New size:', s.length);
    process.exit(0);
  }
  
  // Find the closing } of the if block (it's on its own line after https443.listen)
  let afterListen = s.indexOf('\n', end);
  if (afterListen < 0) afterListen = s.length;
  
  // The closing } should be the next non-empty line
  let closeBrace = s.indexOf('\n}', afterListen);
  if (closeBrace >= 0) {
    end = closeBrace + 2; // include \n}
  } else {
    // Fallback: just go to the } after the listen line
    end = s.indexOf('}', afterListen);
    if (end >= 0) end += 1;
    else end = afterListen;
  }
  
  let removed = s.substring(start, end);
  console.log('[FIX] Removing block (' + removed.length + ' chars):');
  console.log(removed.substring(0, 200) + (removed.length > 200 ? '...' : ''));
  
  s = s.substring(0, start) + s.substring(end);
  fs.writeFileSync(FILE, s);
  console.log('[FIX] SUCCESS! New file size:', s.length);
} catch (e) {
  console.error('[FIX] ERROR:', e.message);
  process.exit(1);
}
