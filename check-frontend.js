#!/usr/bin/env node
const fs=require('fs'),zlib=require('zlib');
const s=fs.readFileSync('/app/server.js','utf-8');
const m=s.match(/FRONTEND_GZ_B64='([^']+)'/);
if(!m){console.log('NOT FOUND');process.exit(1);}
const b=Buffer.from(m[1],'base64');
const h=zlib.gunzipSync(b).toString();
console.log('LENGTH:', h.length);
console.log('HAS InjectionPanel:', h.includes('InjectionPanel'));
console.log('HAS ArsenalExecTab:', h.includes('ArsenalExecTab'));
console.log('HAS LinuxArsenalTab:', h.includes('LinuxArsenalTab'));
console.log('HAS ArsenalWithInject:', h.includes('ArsenalWithInject'));
console.log('HAS startInject:', h.includes('startInject'));
console.log('HAS handleInject:', h.includes('handleInject'));
console.log('HAS useState:', h.includes('useState'));
console.log('HAS pageContent:', h.includes('pageContent'));
console.log('HAS Inject Payload:', h.includes('Inject Payload'));
console.log('HAS PAYLOAD INJECTED:', h.includes('PAYLOAD INJECTED'));
// Show 200 chars around 'pageContent' anchor
const idx = h.indexOf('pageContent');
if(idx>=0) console.log('AROUND pageContent:', JSON.stringify(h.substring(Math.max(0,idx-100), idx+100)));
// Show 200 chars around 'arsenal' reference for tab
const aidx = h.indexOf("arsenal:");
if(aidx>=0) console.log('AROUND arsenal:', JSON.stringify(h.substring(Math.max(0,aidx-50), aidx+200)));
