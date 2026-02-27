#!/usr/bin/env node
// ==========================================================
// Patch FRONTEND_GZ_B64 in server.js to embed InjectionPanel
// directly into the compiled React SPA.
// Also updates css-hook.js to skip old injection (no dups).
// ==========================================================
const fs = require('fs');
const zlib = require('zlib');

// ===== THE FULL InjectionPanel + ArsenalWithInject CODE =====
const PANEL_CODE = `
function InjectionPanel(){
var _ce=React.createElement;
var _st=useState('ready'),injectState=_st[0],setInjectState=_st[1];
var _dv=useState([]),devices=_dv[0],setDevices=_dv[1];
var _tp=useState([]),templates=_tp[0],setTemplates=_tp[1];
var _sd=useState(''),selDev=_sd[0],setSelDev=_sd[1];
var _sp=useState(''),selTpl=_sp[0],setSelTpl=_sp[1];
var _pg=useState(0),progress=_pg[0],setProgress=_pg[1];
var _rs=useState(null),result=_rs[0],setResult=_rs[1];
var _er=useState(''),error=_er[0],setError=_er[1];
var _ds=useState({}),devStatus=_ds[0],setDevStatus=_ds[1];
var _ji=useState(null),jobId=_ji[0],setJobId=_ji[1];
var pollRef=useRef(null);
var pingRef=useRef(null);
useEffect(function(){
api('/api/devices').then(function(d){var l=Array.isArray(d)?d:d&&d.devices?d.devices:[];setDevices(l);});
api('/api/payload-templates').then(function(t){var l=Array.isArray(t)?t:t&&t.templates?t.templates:[];setTemplates(l);});
return function(){if(pollRef.current)clearInterval(pollRef.current);if(pingRef.current)clearInterval(pingRef.current);};
},[]);
useEffect(function(){
if(pingRef.current)clearInterval(pingRef.current);
if(!selDev)return;
function doPing(){
fetch('/api/deploy/ping/'+selDev,{credentials:'include'}).then(function(r){return r.json();}).then(function(r){
setDevStatus(function(p){var n={};for(var k in p)n[k]=p[k];n[selDev]=r&&r.reachable?'online':'offline';return n;});
}).catch(function(){setDevStatus(function(p){var n={};for(var k in p)n[k]=p[k];n[selDev]='unknown';return n;});});}
doPing();
pingRef.current=setInterval(doPing,5000);
return function(){if(pingRef.current)clearInterval(pingRef.current);};
},[selDev]);
function handleInject(){
if(!selDev||!selTpl)return;
setInjectState('injecting');setProgress(0);setError('');setResult(null);
api('/api/inject',{method:'POST',body:JSON.stringify({device_id:parseInt(selDev),template_id:selTpl})})
.then(function(r){
if(r.error){setInjectState('error');setError(r.error);return;}
var jid=r.id||r.job_id;
if(!jid){setInjectState('done');setResult(r);return;}
setJobId(jid);var p=5;
pollRef.current=setInterval(function(){
p=Math.min(p+3,95);setProgress(p);
api('/api/inject/jobs/'+jid).then(function(s){
if(s.status==='completed'||s.status==='done'){clearInterval(pollRef.current);setProgress(100);setInjectState('done');setResult(s);}
else if(s.status==='failed'||s.status==='error'){clearInterval(pollRef.current);setInjectState('error');setError(s.error||'Injection fejlede');}
});},2000);
}).catch(function(e){setInjectState('error');setError(e.message);});}
function handleRetry(){
if(jobId){
api('/api/inject/jobs/'+jobId+'/retry',{method:'POST'}).then(function(){
setInjectState('injecting');setProgress(0);setError('');setResult(null);
var p=5;pollRef.current=setInterval(function(){
p=Math.min(p+3,95);setProgress(p);
api('/api/inject/jobs/'+jobId).then(function(s){
if(s.status==='completed'||s.status==='done'){clearInterval(pollRef.current);setProgress(100);setInjectState('done');setResult(s);}
else if(s.status==='failed'||s.status==='error'){clearInterval(pollRef.current);setInjectState('error');setError(s.error||'Retry fejlede');}
});},2000);
}).catch(function(e){setInjectState('error');setError(e.message);});
}else{handleReset();}}
function handleReset(){setInjectState('ready');setProgress(0);setResult(null);setError('');setJobId(null);if(pollRef.current)clearInterval(pollRef.current);}
var selDevObj=devices.find(function(d){return String(d.id)===selDev;});
var selTplObj=templates.find(function(t){return t.id===selTpl||String(t.id)===selTpl;});
var ds=devStatus[selDev];
var compatTypes=['bash_bunny','usb_rubber_ducky','key_croc','shark_jack','omg_cable'];
return _ce('div',{style:{padding:16}},
_ce('h3',{style:{margin:'0 0 16px',fontSize:16,color:'var(--text)',display:'flex',alignItems:'center',gap:8}},
'\\uD83D\\uDC89 Payload Injection'),
injectState==='ready'&&_ce('div',null,
_ce('div',{style:{marginBottom:12}},
_ce('label',{style:{display:'block',fontSize:11,color:'var(--text3)',marginBottom:4,fontWeight:600}},'TARGET DEVICE'),
_ce('select',{value:selDev,onChange:function(e){setSelDev(e.target.value);},
style:{width:'100%',padding:'10px 12px',background:'var(--bg2)',border:'1px solid var(--border)',borderRadius:8,color:'var(--text)',fontSize:13}},
_ce('option',{value:''},'-- V\\u00e6lg target device --'),
devices.filter(function(d){return compatTypes.indexOf(d.type)>=0;}).map(function(d){
return _ce('option',{key:d.id,value:d.id},
d.name+' ('+d.type+')'+(d.status==='online'?' \\u2705':' \\u26AA'));}))),
selDevObj&&_ce('div',{style:{fontSize:11,color:'var(--text3)',marginBottom:12,padding:10,background:'var(--bg)',borderRadius:8,border:'1px solid var(--border)'}},
_ce('div',{style:{display:'flex',justifyContent:'space-between',marginBottom:4}},
_ce('span',null,'\\uD83D\\uDCE1 '+selDevObj.name),
_ce('span',{style:{fontWeight:600,color:ds==='online'?'#10b981':ds==='offline'?'#ef4444':'var(--text3)'}},
ds==='online'?'\\u2705 REACHABLE':ds==='offline'?'\\u26D4 UNREACHABLE':'\\u23F3 Pinging...')),
_ce('div',null,'Type: '+selDevObj.type+' | VPN: '+(selDevObj.vpn_ip||'none')+' | Status: '+selDevObj.status)),
_ce('div',{style:{marginBottom:12}},
_ce('label',{style:{display:'block',fontSize:11,color:'var(--text3)',marginBottom:4,fontWeight:600}},'PAYLOAD TEMPLATE'),
_ce('select',{value:selTpl,onChange:function(e){setSelTpl(e.target.value);},
style:{width:'100%',padding:'10px 12px',background:'var(--bg2)',border:'1px solid var(--border)',borderRadius:8,color:'var(--text)',fontSize:13}},
_ce('option',{value:''},'-- V\\u00e6lg payload template --'),
templates.map(function(t){return _ce('option',{key:t.id,value:t.id},t.name+(t.risk?' (\\u26A0 '+t.risk+')':''));}))),
selTplObj&&_ce('div',{style:{fontSize:11,color:'var(--text3)',marginBottom:16,padding:10,background:'var(--bg)',borderRadius:8,border:'1px solid var(--border)'}},
'\\uD83D\\uDCC4 '+selTplObj.name+' | Risk: '+(selTplObj.risk||'?')+' | OS: '+(selTplObj.os||'?')+' | Time: '+(selTplObj.time||'?')),
_ce('button',{disabled:!selDev||!selTpl,onClick:handleInject,
style:{width:'100%',padding:'14px',fontSize:15,fontWeight:700,
background:(!selDev||!selTpl)?'var(--border)':'#10b981',
color:(!selDev||!selTpl)?'var(--text3)':'#fff',
borderRadius:10,border:'none',cursor:(!selDev||!selTpl)?'not-allowed':'pointer',
letterSpacing:0.5,transition:'all 0.2s'}},'\\uD83D\\uDC89 Inject Payload')),
injectState==='injecting'&&_ce('div',{style:{textAlign:'center',padding:'40px 0'}},
_ce('div',{style:{fontSize:48,marginBottom:16}},'\\u23F3'),
_ce('div',{style:{fontSize:16,fontWeight:700,color:'var(--text)',marginBottom:8}},'Injecting payload...'),
_ce('div',{style:{fontSize:12,color:'var(--text3)',marginBottom:16}},
(selTplObj?selTplObj.name:'payload')+' \\u2192 '+(selDevObj?selDevObj.name:'device')),
_ce('div',{style:{width:'100%',height:10,background:'var(--bg2)',borderRadius:5,overflow:'hidden'}},
_ce('div',{style:{width:progress+'%',height:'100%',background:'linear-gradient(90deg,#10b981,#34d399)',borderRadius:5,transition:'width 0.3s ease'}})),
_ce('div',{style:{fontSize:11,color:'var(--text3)',marginTop:8}},progress+'%'),
_ce('div',{style:{fontSize:10,color:'var(--text3)',marginTop:12,fontStyle:'italic'}},
progress<30?'Compiling payload...':progress<60?'Delivering to agent...':progress<90?'Writing to device...':'Verifying...')),
injectState==='done'&&_ce('div',{style:{textAlign:'center',padding:'40px 0'}},
_ce('div',{style:{fontSize:48,marginBottom:12}},'\\u2705'),
_ce('div',{style:{fontSize:20,fontWeight:700,color:'#10b981',marginBottom:16,letterSpacing:1}},'\\u2705 PAYLOAD INJECTED'),
selDevObj&&_ce('div',{style:{fontSize:13,color:'var(--text)',marginBottom:4}},
selDevObj.name+' ('+selDevObj.type+')'),
selDevObj&&selDevObj.vpn_ip&&_ce('div',{style:{fontSize:11,color:'var(--text3)',marginBottom:4}},'VPN: '+selDevObj.vpn_ip),
selTplObj&&_ce('div',{style:{fontSize:11,color:'var(--text3)',marginBottom:16}},'Template: '+selTplObj.name),
result&&result.strategy&&_ce('div',{style:{fontSize:11,color:'var(--text3)',marginBottom:16,padding:8,background:'var(--bg)',borderRadius:6}},
'Strategy: '+result.strategy+(result.agent_name?' via '+result.agent_name:'')),
_ce('button',{onClick:handleReset,
style:{padding:'12px 36px',fontSize:14,fontWeight:600,background:'#10b981',color:'#fff',border:'none',borderRadius:8,cursor:'pointer'}},'Inject Again')),
injectState==='error'&&_ce('div',{style:{textAlign:'center',padding:'40px 0'}},
_ce('div',{style:{fontSize:48,marginBottom:12}},'\\u274C'),
_ce('div',{style:{fontSize:20,fontWeight:700,color:'#ef4444',marginBottom:12}},'\\u274C FEJLET'),
_ce('div',{style:{fontSize:12,color:'#ef4444',marginBottom:16,padding:12,background:'#ef444411',borderRadius:8,border:'1px solid #ef444433',textAlign:'left'}},error),
_ce('div',{style:{display:'flex',gap:8,justifyContent:'center'}},
_ce('button',{onClick:handleRetry,
style:{padding:'10px 24px',fontSize:13,fontWeight:600,background:'#f59e0b',color:'#000',border:'none',borderRadius:8,cursor:'pointer'}},'\\u21BB Retry'),
_ce('button',{onClick:handleReset,
style:{padding:'10px 24px',fontSize:13,fontWeight:600,background:'var(--bg2)',color:'var(--text)',border:'1px solid var(--border)',borderRadius:8,cursor:'pointer'}},'Start Over'))));}
function ArsenalWithInject(){
var _m=useState('arsenal'),mode=_m[0],setMode=_m[1];
var _ce=React.createElement;
return _ce('div',null,
_ce('div',{style:{display:'flex',gap:8,marginBottom:12,padding:'0 12px'}},
_ce('button',{onClick:function(){setMode('arsenal');},
style:{padding:'8px 20px',fontSize:12,fontWeight:600,borderRadius:6,border:'1px solid var(--border)',cursor:'pointer',
background:mode==='arsenal'?'var(--accent)':'var(--bg2)',color:mode==='arsenal'?'#000':'var(--text3)',transition:'all 0.15s'}},
'\\u2694\\uFE0F Arsenal'),
_ce('button',{onClick:function(){setMode('inject');},
style:{padding:'8px 20px',fontSize:12,fontWeight:600,borderRadius:6,border:'1px solid var(--border)',cursor:'pointer',
background:mode==='inject'?'#10b981':'var(--bg2)',color:mode==='inject'?'#fff':'var(--text3)',transition:'all 0.15s'}},
'\\uD83D\\uDC89 Injection')),
mode==='arsenal'?_ce(ArsenalExecTab,null):_ce(InjectionPanel,null));}
`;

// ===== PATCH LOGIC =====

const serverFiles = ['/data/server-v4.3.js', '/app/server.js'];

for (const f of serverFiles) {
  if (!fs.existsSync(f)) { console.log('SKIP:', f); continue; }

  let s = fs.readFileSync(f, 'utf-8');

  // Find FRONTEND_GZ_B64
  const startMarker = "FRONTEND_GZ_B64='";
  const startIdx = s.indexOf(startMarker);
  if (startIdx < 0) {
    console.log('ERROR: FRONTEND_GZ_B64 not found in', f);
    continue;
  }

  const b64Start = startIdx + startMarker.length;
  const b64End = s.indexOf("'", b64Start);
  if (b64End < 0) {
    console.log('ERROR: Could not find end of FRONTEND_GZ_B64 in', f);
    continue;
  }

  const b64 = s.substring(b64Start, b64End);
  console.log('B64 length:', b64.length, 'in', f);

  // Decompress
  let html;
  try {
    html = zlib.gunzipSync(Buffer.from(b64, 'base64')).toString();
  } catch (e) {
    console.log('ERROR: Could not decompress FRONTEND_GZ_B64:', e.message);
    continue;
  }
  console.log('HTML length:', html.length);

  // Check if already patched
  if (html.includes('handleInject') && html.includes('PAYLOAD INJECTED')) {
    console.log('ALREADY PATCHED (FRONTEND_GZ_B64):', f);
    continue;
  }

  // Find anchor: ;const pageContent={
  const anchor = ';const pageContent={';
  const anchorIdx = html.indexOf(anchor);
  if (anchorIdx < 0) {
    // Try alternative anchor
    const alt = 'const pageContent={';
    const altIdx = html.indexOf(alt);
    if (altIdx < 0) {
      console.log('ERROR: pageContent anchor NOT FOUND in', f);
      // Try to find what we can use
      const samples = ['pageContent', 'ArsenalExecTab', 'LinuxArsenalTab'];
      for (const sm of samples) {
        const si = html.indexOf(sm);
        console.log('  Search "' + sm + '":', si >= 0 ? 'FOUND at ' + si : 'NOT FOUND');
      }
      continue;
    }
    // Insert before 'const pageContent={'
    console.log('Using alt anchor at', altIdx);
    html = html.substring(0, altIdx) + PANEL_CODE + html.substring(altIdx);
  } else {
    // Insert after the semicolon, before 'const pageContent={'
    html = html.substring(0, anchorIdx + 1) + PANEL_CODE + html.substring(anchorIdx + 1);
  }
  console.log('INJECTED InjectionPanel code');

  // Replace LinuxArsenalTab reference with ArsenalWithInject
  // The pattern is: React.createElement(LinuxArsenalTab,{engagement:null})
  // We need to be careful to only replace the arsenal tab reference, not other occurrences
  let replaced = false;

  // Try LinuxArsenalTab first
  if (html.includes('LinuxArsenalTab')) {
    // Replace just the createElement call in the pageContent arsenal entry
    const oldRef = 'React.createElement(LinuxArsenalTab,{engagement:null})';
    const newRef = 'React.createElement(ArsenalWithInject,null)';
    if (html.includes(oldRef)) {
      html = html.replace(oldRef, newRef);
      replaced = true;
      console.log('REPLACED: LinuxArsenalTab -> ArsenalWithInject (full pattern)');
    } else {
      // Try without the engagement prop
      const oldRef2 = 'React.createElement(LinuxArsenalTab,';
      if (html.includes(oldRef2)) {
        // Find and replace just this one createElement call
        const refIdx = html.indexOf(oldRef2);
        // Find the closing paren
        let depth = 0;
        let end = refIdx;
        for (let i = refIdx; i < html.length; i++) {
          if (html[i] === '(') depth++;
          if (html[i] === ')') { depth--; if (depth === 0) { end = i + 1; break; } }
        }
        const oldCall = html.substring(refIdx, end);
        html = html.replace(oldCall, 'React.createElement(ArsenalWithInject,null)');
        replaced = true;
        console.log('REPLACED: LinuxArsenalTab call -> ArsenalWithInject');
      }
    }
  }

  // Try ArsenalExecTab
  if (!replaced && html.includes('ArsenalExecTab')) {
    const oldRef = 'React.createElement(ArsenalExecTab,';
    if (html.includes(oldRef)) {
      const refIdx = html.indexOf(oldRef);
      let depth = 0;
      let end = refIdx;
      for (let i = refIdx; i < html.length; i++) {
        if (html[i] === '(') depth++;
        if (html[i] === ')') { depth--; if (depth === 0) { end = i + 1; break; } }
      }
      const oldCall = html.substring(refIdx, end);
      html = html.replace(oldCall, 'React.createElement(ArsenalWithInject,null)');
      replaced = true;
      console.log('REPLACED: ArsenalExecTab call -> ArsenalWithInject');
    }
  }

  if (!replaced) {
    console.log('WARN: Could not find ArsenalExecTab or LinuxArsenalTab to replace');
    // Search for arsenal-related strings
    const arsIdx = html.indexOf('arsenal:');
    if (arsIdx >= 0) {
      console.log('  Found "arsenal:" at', arsIdx, ':', JSON.stringify(html.substring(arsIdx, arsIdx + 200)));
    }
  }

  // Recompress
  const newB64 = zlib.gzipSync(Buffer.from(html), { level: 9 }).toString('base64');
  console.log('New B64 length:', newB64.length, '(was', b64.length, ')');

  // Replace in server source
  s = s.substring(0, b64Start) + newB64 + s.substring(b64End);
  fs.writeFileSync(f, s);
  console.log('PATCHED FRONTEND_GZ_B64:', f);
}

// ===== UPDATE css-hook.js TO SKIP OLD INJECTION =====
const hookPath = '/data/css-hook.js';
if (fs.existsSync(hookPath)) {
  let hook = fs.readFileSync(hookPath, 'utf-8');

  // Add guard to skip InjectionPanel injection if already in HTML
  const oldGuard = "if(injIdx >= 0){";
  const newGuard = "if(injIdx >= 0 && !h.includes('function InjectionPanel')){";

  if (hook.includes(newGuard)) {
    console.log('css-hook.js: Guard already present');
  } else if (hook.includes("if(injIdx >= 0 && !h.includes")) {
    console.log('css-hook.js: Similar guard exists');
  } else {
    // Find the specific injection block for InjectionPanel
    const injBlockMarker = "const injPanelCode = Buffer.from(";
    const injBlockIdx = hook.indexOf(injBlockMarker);
    if (injBlockIdx >= 0) {
      // Find the 'if(injIdx >= 0){' right after the anchor setup
      const guardSearch = hook.indexOf(oldGuard, injBlockIdx);
      if (guardSearch >= 0 && guardSearch < injBlockIdx + 500) {
        hook = hook.substring(0, guardSearch) + newGuard + hook.substring(guardSearch + oldGuard.length);
        fs.writeFileSync(hookPath, hook);
        console.log('css-hook.js: Added guard to skip if InjectionPanel exists');
      } else {
        console.log('css-hook.js: Could not find guard location near injection block');
      }
    } else {
      console.log('css-hook.js: InjectionPanel injection block not found (ok if not present)');
    }
  }
} else {
  console.log('css-hook.js: Not found at', hookPath);
}

console.log('\nDone. Restart server to apply.');
console.log('Verify: curl -s http://localhost:3000/ | grep -c "handleInject"');
console.log('Verify: curl -s http://localhost:3000/ | grep -c "PAYLOAD INJECTED"');
