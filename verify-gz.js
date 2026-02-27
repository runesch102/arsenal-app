const fs=require('fs'),zlib=require('zlib');
const f=process.argv[2]||'/app/server.js';
const s=fs.readFileSync(f,'utf-8');
let sm='FRONTEND_GZ_B64="',q='"';
let si=s.indexOf(sm);
if(si<0){sm="FRONTEND_GZ_B64='";q="'";si=s.indexOf(sm);}
if(si<0){console.log('NOT FOUND');process.exit(1);}
const bs=si+sm.length,be=s.indexOf(q,bs);
const b64=s.substring(bs,be);
console.log('B64_LEN:',b64.length,'FILE:',f);
const h=zlib.gunzipSync(Buffer.from(b64,'base64')).toString();
console.log('HTML_LEN:',h.length);
var checks=['handleInject','injectState','InjectionPanel','ArsenalWithInject',
  'PAYLOAD INJECTED','Inject Payload','FEJLET','handleRetry','doPing','devStatus',
  'startInject','LinuxArsenalTab','ArsenalExecTab','pageContent'];
checks.forEach(function(c){console.log(c+':',h.includes(c));});
