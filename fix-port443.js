// fix-port443.js v2 - Remove PORT_443_LISTENER block from server.js
// Preserves the closing }); of the app.listen callback
const fs = require('fs');
const FILE = '/data/server-v4.3.js';

try {
  let s = fs.readFileSync(FILE, 'utf8');
  console.log('[FIX] File size:', s.length);
  
  if (!s.includes('PORT_443_LISTENER')) {
    console.log('[FIX] No PORT_443_LISTENER found - file is clean');
    process.exit(0);
  }
  
  // Find the PORT_443_LISTENER block
  let commentIdx = s.indexOf('// PORT_443_LISTENER');
  let blockStart = s.lastIndexOf('\n', commentIdx); // newline before comment
  
  // Find the end of the block: the if-block closing }
  let listenIdx = s.indexOf('https443.listen(', commentIdx);
  if (listenIdx < 0) {
    console.log('[FIX] WARNING: PORT_443_LISTENER found but no https443.listen');
    // Remove just the comment line
    let lineEnd = s.indexOf('\n', commentIdx);
    s = s.substring(0, blockStart) + s.substring(lineEnd);
    fs.writeFileSync(FILE, s);
    console.log('[FIX] Removed comment line. New size:', s.length);
    process.exit(0);
  }
  
  // Find the closing } of the if block
  // It should be on its own line after https443.listen
  let afterListen = s.indexOf('\n', listenIdx);
  let closeBrace = s.indexOf('\n}', afterListen);
  
  if (closeBrace >= 0) {
    // Remove from blockStart to closeBrace+2 (including \n})
    // IMPORTANT: Keep everything after the closing brace (the }); etc)
    let blockEnd = closeBrace + 2;
    let removed = s.substring(blockStart, blockEnd);
    console.log('[FIX] Removing', removed.length, 'chars');
    s = s.substring(0, blockStart) + s.substring(blockEnd);
  } else {
    console.log('[FIX] WARNING: could not find closing brace, doing minimal removal');
    let blockEnd = afterListen;
    s = s.substring(0, blockStart) + s.substring(blockEnd);
  }
  
  fs.writeFileSync(FILE, s);
  console.log('[FIX] SUCCESS! New size:', s.length);
  
  // Verify: check if the file still has proper structure
  if (!s.includes('});')) {
    console.log('[FIX] WARNING: file may be missing closing });');
    // Add it back
    s = s.trimEnd() + '\n});\n';
    fs.writeFileSync(FILE, s);
    console.log('[FIX] Added missing }); - Final size:', s.length);
  }
} catch (e) {
  console.error('[FIX] ERROR:', e.message);
  process.exit(1);
}
