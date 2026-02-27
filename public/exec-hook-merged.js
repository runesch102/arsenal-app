/* ================================================================
   exec-hook-merged.js — Arsenal Attack Planner
   Fixed: showPlan state, AttackPlanPanel rendering, dedup, severity sort
   ================================================================ */

// ── Server-side: Express routes for /api/arsenal/analyze ──
// This section is loaded by the backend (Node.js / Express)

const { execSync } = require('child_process');
const net = require('net');

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };

// Attack templates keyed by service/port patterns
const attackTemplates = [
  // SSH
  { match: p => p.service.match(/ssh/i), name: 'SSH Brute Force', severity: 'high', module: 'ssh_bruteforce', description: 'Attempt SSH login with common credentials' },
  { match: p => p.service.match(/ssh/i), name: 'SSH Key Enumeration', severity: 'medium', module: 'ssh_enum', description: 'Enumerate SSH host keys and algorithms' },
  // HTTP/HTTPS
  { match: p => p.service.match(/http/i) && !p.service.match(/https/i), name: 'SQL Injection Scan', severity: 'critical', module: 'sqli_scan', description: 'Detect SQL injection points in web parameters' },
  { match: p => p.service.match(/http/i), name: 'XSS Detection', severity: 'high', module: 'xss_detect', description: 'Scan for reflected and stored XSS vulnerabilities' },
  { match: p => p.service.match(/http/i), name: 'Directory Bruteforce', severity: 'medium', module: 'dir_bruteforce', description: 'Discover hidden directories and files' },
  { match: p => p.service.match(/http/i), name: 'CORS Misconfiguration', severity: 'medium', module: 'cors_misconfig', description: 'Detect overly permissive CORS policies' },
  { match: p => p.service.match(/http/i), name: 'Command Injection', severity: 'critical', module: 'cmd_injection', description: 'Test for OS command injection vulnerabilities' },
  { match: p => p.service.match(/http/i), name: 'SSRF Detection', severity: 'high', module: 'ssrf_detect', description: 'Test for server-side request forgery' },
  { match: p => p.service.match(/http/i), name: 'File Upload Bypass', severity: 'high', module: 'upload_bypass', description: 'Test file upload restrictions for bypass' },
  { match: p => p.service.match(/http/i) && !p.service.match(/https/i), name: 'HTTP Verb Tampering', severity: 'low', module: 'http_verbtamper', description: 'Test for HTTP verb tampering vulnerabilities' },
  // SSL/TLS
  { match: p => p.service.match(/ssl|https|tls/i) || p.port === 443, name: 'SSL/TLS Weakness', severity: 'medium', module: 'ssl_audit', description: 'Check for weak ciphers and protocol versions' },
  { match: p => p.service.match(/ssl|https|tls/i) || p.port === 443, name: 'Certificate Validation', severity: 'low', module: 'cert_validate', description: 'Verify certificate chain and expiry' },
  // MySQL
  { match: p => p.service.match(/mysql/i), name: 'MySQL Auth Bypass', severity: 'critical', module: 'mysql_authbypass', description: 'Test for MySQL authentication bypass (CVE-2012-2122)' },
  { match: p => p.service.match(/mysql/i), name: 'MySQL Default Creds', severity: 'high', module: 'mysql_defaultcreds', description: 'Test MySQL with default credentials' },
  // PostgreSQL
  { match: p => p.service.match(/postgres/i), name: 'PostgreSQL Default Creds', severity: 'high', module: 'pg_defaultcreds', description: 'Test PostgreSQL with default credentials' },
  // FTP
  { match: p => p.service.match(/ftp/i), name: 'FTP Anonymous Login', severity: 'high', module: 'ftp_anon', description: 'Test for anonymous FTP access' },
  { match: p => p.service.match(/ftp/i), name: 'FTP Brute Force', severity: 'medium', module: 'ftp_bruteforce', description: 'Attempt FTP login with common credentials' },
  // SMTP
  { match: p => p.service.match(/smtp/i), name: 'SMTP Open Relay', severity: 'critical', module: 'smtp_relay', description: 'Test for open mail relay' },
  { match: p => p.service.match(/smtp/i), name: 'SMTP User Enumeration', severity: 'medium', module: 'smtp_enum', description: 'Enumerate valid email addresses via VRFY/EXPN' },
  // DNS
  { match: p => p.service.match(/dns|domain/i), name: 'DNS Zone Transfer', severity: 'high', module: 'dns_axfr', description: 'Attempt DNS zone transfer (AXFR)' },
  // Redis
  { match: p => p.service.match(/redis/i), name: 'Redis Unauth Access', severity: 'critical', module: 'redis_noauth', description: 'Test for unauthenticated Redis access' },
  // Generic
  { match: p => p.service.match(/vnc/i), name: 'VNC Auth Bypass', severity: 'critical', module: 'vnc_authbypass', description: 'Test for VNC authentication bypass' },
  { match: p => p.service.match(/telnet/i), name: 'Telnet Default Creds', severity: 'high', module: 'telnet_creds', description: 'Test Telnet with default credentials' },
  { match: p => p.service.match(/smb|microsoft-ds|netbios/i), name: 'SMB EternalBlue', severity: 'critical', module: 'smb_eternalblue', description: 'Test for MS17-010 EternalBlue vulnerability' },
  { match: p => p.service.match(/rdp|ms-wbt/i), name: 'RDP BlueKeep', severity: 'critical', module: 'rdp_bluekeep', description: 'Test for CVE-2019-0708 BlueKeep vulnerability' },
];

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
    if (osMatch && currentHost) {
      currentHost.os = osMatch[1].trim();
      continue;
    }

    // ONLY match open ports — skip filtered/closed
    const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(open)\s+(\S+)\s*(.*)/);
    if (portMatch && currentHost) {
      currentHost.ports.push({
        port: parseInt(portMatch[1]),
        protocol: portMatch[2],
        state: portMatch[3],
        service: portMatch[4],
        version: portMatch[5] ? portMatch[5].trim() : '',
      });
    }
  }
  if (currentHost) hosts.push(currentHost);
  return hosts;
}

function generateAttacks(hosts) {
  const attacks = [];
  const seen = new Set();

  for (const host of hosts) {
    for (const port of host.ports) {
      for (const tpl of attackTemplates) {
        if (tpl.match(port)) {
          // Deduplicate: unique by attack name + host IP
          const key = `${host.ip}:${tpl.name}`;
          if (seen.has(key)) continue;
          seen.add(key);

          attacks.push({
            name: tpl.name,
            severity: tpl.severity,
            port: port.port,
            service: port.service,
            version: port.version,
            module: tpl.module,
            description: tpl.description,
            host: host.ip,
          });
        }
      }
    }
  }

  // Sort: critical first, then high, medium, low
  attacks.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  attacks.forEach((atk, i) => { atk.id = i + 1; });
  return attacks;
}

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

// TCP connect scan fallback
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

// Register Arsenal analyze route on an Express app
function registerArsenalRoutes(app) {
  app.post('/api/arsenal/analyze', async (req, res) => {
    const { target, scanOutput } = req.body;

    if (!target && !scanOutput) {
      return res.status(400).json({ error: 'Target or scanOutput is required' });
    }

    let nmapOutput = '';
    let scanMethod = 'nmap';
    let hosts = [];

    // If pre-parsed scan output is provided, use it directly (skip nmap)
    if (scanOutput) {
      nmapOutput = scanOutput;
      scanMethod = 'provided';
      hosts = parseNmapOutput(nmapOutput);
    } else {
      if (!/^[a-zA-Z0-9._:-]+$/.test(target)) {
        return res.status(400).json({ error: 'Invalid target format' });
      }

      try {
        nmapOutput = execSync(
          `nmap -sV -T4 --open -Pn ${target}`,
          { timeout: 120000, encoding: 'utf-8' }
        );
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
            hosts = [{
              ip: target, hostname: target, os: 'Unknown',
              ports: openPorts.map(r => ({
                port: r.port, protocol: 'tcp', state: 'open',
                service: portServiceMap[r.port] || 'unknown', version: '',
              })),
            }];
          }
        } catch (err) { /* TCP scan failed */ }
      }
    }

    if (hosts.length === 0) {
      return res.json({
        hosts: [], attacks: [],
        summary: { totalHosts: 0, totalAttacks: 0, critical: 0, high: 0, medium: 0, low: 0 },
        scanMethod, nmapRaw: nmapOutput,
        error: 'No open ports found. Target may be unreachable from this network.',
      });
    }

    const attacks = generateAttacks(hosts);
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of attacks) counts[a.severity]++;

    res.json({
      hosts: hosts.map(h => ({
        ip: h.ip, hostname: h.hostname, os: h.os || 'Unknown',
        ports: h.ports.map(p => ({
          port: p.port, protocol: p.protocol, state: p.state,
          service: p.service, version: p.version,
        })),
      })),
      attacks,
      summary: { totalHosts: hosts.length, totalAttacks: attacks.length, ...counts },
      scanMethod, nmapRaw: nmapOutput,
    });
  });
}

// ── Frontend: ArsenalExecTab + AttackPlanPanel (React component) ──
// Rendered as inline HTML for the Arsenal tab

const ARSENAL_FRONTEND_HTML = `
<style>
  .arsenal-wrap { max-width: 960px; margin: 0 auto; padding: 32px 16px; }
  .arsenal-wrap h1 { font-size: 28px; font-weight: 700; color: #4fc3f7; margin-bottom: 4px; }
  .arsenal-wrap h1 span { color: #8892a4; font-weight: 400; font-size: 16px; }
  .arsenal-wrap .subtitle { color: #5a6a84; margin-bottom: 24px; font-size: 14px; }
  .arsenal-wrap .input-row { display: flex; gap: 12px; margin-bottom: 24px; background: #141a2a; border: 1px solid #1e2940; border-radius: 8px; padding: 16px; }
  .arsenal-wrap .input-row input { flex: 1; padding: 10px 14px; border-radius: 6px; border: 1px solid #2a3550; background: #0d1220; color: #e0e0e0; font-size: 15px; outline: none; }
  .arsenal-wrap .input-row button { padding: 10px 28px; border-radius: 6px; border: none; background: #4fc3f7; color: #0a0e17; font-weight: 700; font-size: 15px; cursor: pointer; transition: background .2s; }
  .arsenal-wrap .input-row button:disabled { background: #2a3550; cursor: wait; }
  .arsenal-wrap .error-box { background: #2a1015; border: 1px solid #ff4444; border-radius: 8px; padding: 14px; margin-bottom: 20px; color: #ff6b6b; }
  .arsenal-wrap h2 { font-size: 18px; color: #4fc3f7; margin-bottom: 12px; }
  .arsenal-wrap .stats { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 28px; }
  .arsenal-wrap .stat-card { background: #141a2a; border: 1px solid #1e2940; border-radius: 8px; padding: 16px 20px; text-align: center; min-width: 100px; }
  .arsenal-wrap .stat-card .val { font-size: 28px; font-weight: 700; color: #4fc3f7; }
  .arsenal-wrap .stat-card .lbl { font-size: 12px; color: #8892a4; margin-top: 4px; }
  .arsenal-wrap .host-card { background: #141a2a; border: 1px solid #1e2940; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  .arsenal-wrap .host-ip { color: #4fc3f7; font-weight: 700; }
  .arsenal-wrap .host-name { color: #8892a4; margin-left: 12px; }
  .arsenal-wrap .host-os { color: #5a6a84; font-size: 13px; margin-left: 12px; }
  .arsenal-wrap .port-tags { margin-top: 8px; display: flex; gap: 6px; flex-wrap: wrap; }
  .arsenal-wrap .port-tag { background: #1a2236; border: 1px solid #2a3550; border-radius: 4px; padding: 2px 8px; font-size: 12px; color: #8892a4; }
  .arsenal-wrap .port-tag .svc { color: #4fc3f7; margin-left: 4px; }
  .arsenal-wrap .tbl-wrap { background: #141a2a; border: 1px solid #1e2940; border-radius: 8px; overflow: hidden; }
  .arsenal-wrap table { width: 100%; border-collapse: collapse; }
  .arsenal-wrap th { padding: 10px 14px; text-align: left; font-size: 12px; color: #5a6a84; font-weight: 600; background: #1a2236; border-bottom: 1px solid #1e2940; }
  .arsenal-wrap td { padding: 10px 14px; border-bottom: 1px solid #1a2236; font-size: 13px; }
  .arsenal-wrap td.name { font-weight: 600; color: #e0e0e0; }
  .arsenal-wrap td.mod { font-family: monospace; color: #4fc3f7; }
  .arsenal-wrap td.desc { color: #8892a4; }
  .arsenal-wrap td.port { color: #8892a4; }
  .arsenal-wrap .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 700; text-transform: uppercase; color: #000; }
  .arsenal-wrap .badge-critical { background: #ff4444; }
  .arsenal-wrap .badge-high { background: #ff8c00; }
  .arsenal-wrap .badge-medium { background: #ffd700; }
  .arsenal-wrap .badge-low { background: #4caf50; }
  .arsenal-wrap .nmap-raw { background: #0d1220; border: 1px solid #1e2940; border-radius: 8px; padding: 16px; margin-top: 28px; font-family: monospace; font-size: 12px; color: #5a6a84; white-space: pre-wrap; max-height: 300px; overflow-y: auto; }
</style>
<div class="arsenal-wrap" id="arsenal-root"></div>
<script>
(function() {
  var root = document.getElementById('arsenal-root');

  // ── State ──
  var target = '';
  var loading = false;
  var error = null;
  var attackPlan = null;
  var showPlan = false;

  // State setter functions (React-compatible naming)
  function setShowPlan(v) { showPlan = v; }
  function setAttackPlan(v) { attackPlan = v; }

  function render() {
    var html = '';
    html += '<h1>Arsenal <span>// Attack Planner</span></h1>';
    html += '<p class="subtitle">Analysér et mål og generer en attack plan baseret på åbne porte og kendte sårbarheder.</p>';

    // Input row
    html += '<div class="input-row">';
    html += '<input id="arsenal-target" type="text" value="' + escHtml(target) + '" placeholder="Target IP / hostname">';
    html += '<button id="arsenal-btn"' + (loading ? ' disabled' : '') + '>' + (loading ? 'Analyserer…' : 'Analysér') + '</button>';
    html += '</div>';

    if (error) {
      html += '<div class="error-box">Fejl: ' + escHtml(error) + '</div>';
    }

    // ── AttackPlanPanel — only rendered when showPlan is true ──
    if (showPlan && attackPlan) {
      html += renderAttackPlanPanel(attackPlan);
    }

    root.innerHTML = html;

    // Bind events
    var inp = document.getElementById('arsenal-target');
    var btn = document.getElementById('arsenal-btn');
    if (inp) {
      inp.addEventListener('input', function(e) { target = e.target.value; });
      inp.addEventListener('keydown', function(e) { if (e.key === 'Enter') handleAnalyze(); });
    }
    if (btn) btn.addEventListener('click', handleAnalyze);
  }

  function renderAttackPlanPanel(plan) {
    var h = '';

    // Summary
    h += '<h2>Opsummering</h2>';
    h += '<div class="stats">';
    h += statCard('Hosts', plan.summary.totalHosts, '');
    h += statCard('Attacks', plan.summary.totalAttacks, '');
    h += statCard('Critical', plan.summary.critical, '#ff4444');
    h += statCard('High', plan.summary.high, '#ff8c00');
    h += statCard('Medium', plan.summary.medium, '#ffd700');
    h += statCard('Low', plan.summary.low, '#4caf50');
    h += '</div>';

    // Hosts
    h += '<h2>Hosts</h2>';
    for (var i = 0; i < plan.hosts.length; i++) {
      var host = plan.hosts[i];
      h += '<div class="host-card">';
      h += '<span class="host-ip">' + escHtml(host.ip) + '</span>';
      h += '<span class="host-name">' + escHtml(host.hostname) + '</span>';
      h += '<span class="host-os">OS: ' + escHtml(host.os) + '</span>';
      h += '<div class="port-tags">';
      for (var j = 0; j < host.ports.length; j++) {
        var p = host.ports[j];
        h += '<span class="port-tag">:' + p.port + '<span class="svc">' + escHtml(p.service) + (p.version ? ' ' + escHtml(p.version) : '') + '</span></span>';
      }
      h += '</div></div>';
    }

    // Attack table
    h += '<h2>Attack Plan</h2>';
    h += '<div class="tbl-wrap"><table>';
    h += '<thead><tr><th>#</th><th>Attack</th><th>Severity</th><th>Port</th><th>Module</th><th>Beskrivelse</th></tr></thead>';
    h += '<tbody>';
    for (var k = 0; k < plan.attacks.length; k++) {
      var a = plan.attacks[k];
      h += '<tr>';
      h += '<td>' + a.id + '</td>';
      h += '<td class="name">' + escHtml(a.name) + '</td>';
      h += '<td><span class="badge badge-' + a.severity + '">' + a.severity + '</span></td>';
      h += '<td class="port">:' + a.port + '</td>';
      h += '<td class="mod">' + escHtml(a.module) + '</td>';
      h += '<td class="desc">' + escHtml(a.description) + '</td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    // Raw nmap output
    if (plan.nmapRaw) {
      h += '<h2 style="margin-top:28px">Nmap Output</h2>';
      h += '<div class="nmap-raw">' + escHtml(plan.nmapRaw) + '</div>';
    }

    return h;
  }

  function statCard(label, value, color) {
    return '<div class="stat-card"><div class="val" style="color:' + (color || '#4fc3f7') + '">' + value + '</div><div class="lbl">' + label + '</div></div>';
  }

  function handleAnalyze() {
    if (loading || !target.trim()) return;
    loading = true;
    error = null;
    setShowPlan(false);
    setAttackPlan(null);
    render();

    fetch('/api/arsenal/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: target.trim() })
    })
    .then(function(res) {
      if (!res.ok) throw new Error('Server responded ' + res.status);
      return res.json();
    })
    .then(function(data) {
      setAttackPlan(data);
      setShowPlan(true);
      loading = false;
      render();
    })
    .catch(function(err) {
      error = err.message;
      loading = false;
      render();
    });
  }

  function escHtml(s) {
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  render();
})();
</script>
`;

// ── React Component version (for React-based apps) ──
// Use this if your app uses React with hooks

function ArsenalExecTab({ React, useState }) {
  const _React = React || (typeof window !== 'undefined' && window.React);
  const _useState = useState || (_React && _React.useState);

  if (!_React || !_useState) {
    return null;
  }

  const [target, setTarget] = _useState('');
  const [loading, setLoading] = _useState(false);
  const [error, setError] = _useState(null);
  const [showPlan, setShowPlan] = _useState(false);
  const [attackPlan, setAttackPlan] = _useState(null);

  const handleAnalyze = async () => {
    if (loading || !target.trim()) return;
    setLoading(true);
    setError(null);
    setShowPlan(false);
    setAttackPlan(null);

    try {
      const res = await fetch('/api/arsenal/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim() }),
      });
      if (!res.ok) throw new Error('Server responded ' + res.status);
      const data = await res.json();
      setAttackPlan(data);
      setShowPlan(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return { target, setTarget, loading, error, showPlan, setShowPlan, attackPlan, setAttackPlan, handleAnalyze };
}

// ── Exports ──
module.exports = {
  registerArsenalRoutes,
  parseNmapOutput,
  generateAttacks,
  attackTemplates,
  severityOrder,
  portServiceMap,
  tcpScan,
  ArsenalExecTab,
  ARSENAL_FRONTEND_HTML,
};

