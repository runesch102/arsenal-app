#!/usr/bin/env node
// Patch heartbeat to auto-assign pending inject_jobs based on connected_devices
// AND enhance inject_job response with target info (drive, path, type)
// Run on server: node /tmp/patch-heartbeat.js
const fs = require('fs');

const files = ['/data/server-v4.3.js', '/app/server.js'];

for (const f of files) {
  if (!fs.existsSync(f)) { console.log('SKIP: ' + f); continue; }
  let s = fs.readFileSync(f, 'utf-8');

  // === PATCH 1: Add inject_jobs matching before the existing assigned-job check ===
  const marker1 = '// Check for pending inject jobs assigned to this agent';
  if (s.includes('// Auto-assign pending inject_jobs')) {
    console.log('ALREADY PATCHED (auto-assign): ' + f);
  } else if (s.includes(marker1)) {
    const autoAssign = `// Auto-assign pending inject_jobs to this agent based on connected_devices
  if(connected_devices&&Array.isArray(connected_devices)&&connected_devices.length>0){
    const pendingJobs=db.prepare("SELECT j.id,j.device_id,d.type as target_type FROM inject_jobs j JOIN devices d ON j.device_id=d.id WHERE j.status='pending' AND j.strategy='agent' AND j.agent_device_id IS NULL ORDER BY j.id ASC").all();
    for(const pj of pendingJobs){
      if(connected_devices.some(cd=>cd.type===pj.target_type)){
        db.prepare("UPDATE inject_jobs SET agent_device_id=?,status='assigned',error=NULL,updated_at=datetime('now') WHERE id=?").run(d.id,pj.id);
        console.log('[HB] Auto-assigned inject job '+pj.id+' to agent '+d.name);
        break;
      }
    }
  }
  `;
    s = s.replace(marker1, autoAssign + marker1);
    console.log('PATCHED (auto-assign): ' + f);
  } else {
    console.log('MARKER NOT FOUND (auto-assign): ' + f);
  }

  // === PATCH 2: Enhance inject_job response with target info ===
  const oldReturn = "return{ok:true,server_ts:new Date().toISOString(),inject_job:{id:injectJob.id,device_id:injectJob.device_id,payload:injectJob.payload,payload_type:injectJob.payload_type}};";
  const newReturn = `{
    const targetDev=db.prepare("SELECT type,name FROM devices WHERE id=?").get(injectJob.device_id);
    let targetDrive=null,payloadPath=null;
    if(connected_devices&&Array.isArray(connected_devices)){
      const match=connected_devices.find(cd=>cd.type===(targetDev&&targetDev.type));
      if(match){
        targetDrive=match.drive||null;
        const dt=targetDev&&targetDev.type;
        if(dt==='bash_bunny')payloadPath=(match.drive||'')+'\\\\payloads\\\\switch1\\\\payload.txt';
        else if(dt==='usb_rubber_ducky')payloadPath=(match.drive||'')+'\\\\inject.bin';
        else if(dt==='key_croc')payloadPath=(match.drive||'')+'\\\\payload.txt';
        else if(dt==='shark_jack')payloadPath=(match.drive||'')+'\\\\payload.sh';
      }
    }
    return{ok:true,server_ts:new Date().toISOString(),inject_jobs:[{job_id:injectJob.id,device_id:injectJob.device_id,payload:injectJob.payload,payload_type:injectJob.payload_type,target_device_type:targetDev&&targetDev.type,target_device_name:targetDev&&targetDev.name,target_drive:targetDrive,payload_path:payloadPath}]};
  }`;

  if (s.includes('inject_jobs:[{job_id:injectJob.id')) {
    console.log('ALREADY PATCHED (response): ' + f);
  } else if (s.includes(oldReturn)) {
    s = s.replace(oldReturn, newReturn);
    console.log('PATCHED (response): ' + f);
  } else {
    console.log('WARN: inject_job return pattern not found in ' + f);
  }

  fs.writeFileSync(f, s);
}

console.log('Done. Restart server to apply.');
