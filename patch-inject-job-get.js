#!/usr/bin/env node
// Patch: Add GET /api/inject/jobs/:id endpoint for InjectionPanel polling
// Run on server: node /tmp/patch-inject-job-get.js
const fs = require('fs');

const files = ['/data/server-v4.3.js', '/app/server.js'];

for (const f of files) {
  if (!fs.existsSync(f)) { console.log('SKIP: ' + f); continue; }
  let s = fs.readFileSync(f, 'utf-8');

  // Check if already patched
  if (s.includes('GET single inject job by id')) {
    console.log('ALREADY PATCHED: ' + f);
    continue;
  }

  // Insert before the DELETE endpoint
  const marker = 'app.delete("/api/inject/jobs/:id"';
  const idx = s.indexOf(marker);
  if (idx < 0) {
    console.log('MARKER NOT FOUND: ' + f);
    continue;
  }

  const newEndpoint = `// GET single inject job by id (for InjectionPanel polling)
app.get("/api/inject/jobs/:id",{preHandler:[app.authenticate]},async(req,reply)=>{
  const job=db.prepare("SELECT j.*,d.name as device_name,d.type as device_type,a.name as agent_name FROM inject_jobs j LEFT JOIN devices d ON j.device_id=d.id LEFT JOIN devices a ON j.agent_device_id=a.id WHERE j.id=?").get(req.params.id);
  if(!job)return reply.code(404).send({error:"Job not found"});
  return job;
});

`;

  s = s.substring(0, idx) + newEndpoint + s.substring(idx);
  fs.writeFileSync(f, s);
  console.log('PATCHED: ' + f);
}

console.log('Done. Restart server to apply.');
