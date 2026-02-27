#!/usr/bin/env node
// Patch pc-agent.ps1:
// 1. Add Find-HakDevice function using Get-WmiObject Win32_LogicalDisk
// 2. Update heartbeat response handling for inject_jobs array format
// 3. Use enhanced job fields (target_drive, payload_path, target_device_type)
// Run on server: node /tmp/patch-pc-agent.js
const fs = require('fs');

const f = '/data/pc-agent.ps1';
if (!fs.existsSync(f)) { console.log('ERROR: ' + f + ' not found'); process.exit(1); }

let s = fs.readFileSync(f, 'utf-8');

// === PATCH 1: Add Find-HakDevice function ===
if (s.includes('Find-HakDevice')) {
  console.log('ALREADY PATCHED: Find-HakDevice');
} else {
  const findHakDevice = `
# Systematic USB device scanning using WMI
function Find-HakDevice {
    $found = @()

    # Get all removable logical disks via WMI
    $disks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue

    foreach ($disk in $disks) {
        $drive = $disk.DeviceID
        $label = $disk.VolumeName
        $size = [math]::Round($disk.Size / 1GB, 2)

        # BashBunny detection: volume label + /payloads/ directory structure
        if ($label -match "BashBunny|YOURBUNN" -or (Test-Path "$drive\\payloads\\switch1")) {
            $found += @{
                type = "bash_bunny"
                label = $label
                drive = $drive
                size_gb = $size
                has_payloads = (Test-Path "$drive\\payloads")
            }
            Write-Host "[+] BashBunny detected: $drive ($label) [$size GB]" -ForegroundColor Green
            continue
        }

        # USB Rubber Ducky detection: volume label + inject.bin presence
        if ($label -match "DUCKY|RubberDucky" -or (Test-Path "$drive\\inject.bin")) {
            $found += @{
                type = "usb_rubber_ducky"
                label = $label
                drive = $drive
                size_gb = $size
                has_inject = (Test-Path "$drive\\inject.bin")
            }
            Write-Host "[+] USB Rubber Ducky detected: $drive ($label) [$size GB]" -ForegroundColor Green
            continue
        }

        # KeyCroc detection: volume label + config.txt or loot/ directory
        if ($label -match "KeyCroc|YOURCROC" -or (Test-Path "$drive\\config.txt" ) -and (Test-Path "$drive\\loot")) {
            $found += @{
                type = "key_croc"
                label = $label
                drive = $drive
                size_gb = $size
                has_config = (Test-Path "$drive\\config.txt")
            }
            Write-Host "[+] KeyCroc detected: $drive ($label) [$size GB]" -ForegroundColor Green
            continue
        }

        # SharkJack detection: volume label + payload.sh
        if ($label -match "SharkJack" -or (Test-Path "$drive\\payload.sh")) {
            $found += @{
                type = "shark_jack"
                label = $label
                drive = $drive
                size_gb = $size
            }
            Write-Host "[+] SharkJack detected: $drive ($label) [$size GB]" -ForegroundColor Green
            continue
        }

        # Unknown removable — log for operator awareness
        if ($label) {
            Write-Host "[?] Unknown removable: $drive ($label) [$size GB]" -ForegroundColor DarkYellow
        }
    }

    # O.MG Cable detection via COM ports
    $comPorts = Get-WmiObject Win32_SerialPort -ErrorAction SilentlyContinue | Where-Object { $_.Description -match "USB|Serial" }
    foreach ($port in $comPorts) {
        if ($port.Description -match "O\\.MG|OMG|CP210") {
            $found += @{
                type = "omg_cable"
                label = $port.Description
                port = $port.DeviceID
            }
            Write-Host "[+] O.MG Cable detected: $($port.DeviceID) ($($port.Description))" -ForegroundColor Green
        }
    }

    return $found
}
`;

  // Insert after the Get-ConnectedHak5Devices function
  const marker = '# Write payload to connected device';
  if (s.includes(marker)) {
    s = s.replace(marker, findHakDevice + '\n' + marker);
    console.log('PATCHED: Find-HakDevice added');
  } else {
    console.log('WARN: Could not find insertion point for Find-HakDevice');
  }
}

// === PATCH 2: Replace Get-ConnectedHak5Devices calls with Find-HakDevice ===
if (s.includes('$connected = Find-HakDevice')) {
  console.log('ALREADY PATCHED: Find-HakDevice calls');
} else {
  // Replace usages in main loop and Invoke-InjectJob
  s = s.replace(/\$connected = Get-ConnectedHak5Devices/g, '$connected = Find-HakDevice');
  s = s.replace(/Get-ConnectedHak5Devices(?!\s*\{)/g, 'Find-HakDevice');
  console.log('PATCHED: Get-ConnectedHak5Devices calls replaced with Find-HakDevice');
}

// === PATCH 3: Update heartbeat response handling for inject_jobs array ===
const oldHeartbeatCheck = `        # Check for inject job in heartbeat response
        if ($resp.inject_job) {
            Write-Host "[!] INJECT JOB RECEIVED: $($resp.inject_job.id)" -ForegroundColor Yellow
            Invoke-InjectJob -Job $resp.inject_job
        }`;

const newHeartbeatCheck = `        # Check for inject jobs in heartbeat response (new array format)
        if ($resp.inject_jobs -and $resp.inject_jobs.Count -gt 0) {
            foreach ($ij in $resp.inject_jobs) {
                $jid = if ($ij.job_id) { $ij.job_id } else { $ij.id }
                Write-Host "[!] INJECT JOB RECEIVED: $jid (target: $($ij.target_device_type))" -ForegroundColor Yellow
                # Use enhanced fields if available
                if ($ij.payload_path) {
                    Write-Host "[>] Target path: $($ij.payload_path)" -ForegroundColor Cyan
                }
                Invoke-InjectJob -Job $ij
            }
        }
        # Backwards compat: old singular inject_job format
        elseif ($resp.inject_job) {
            Write-Host "[!] INJECT JOB RECEIVED: $($resp.inject_job.id)" -ForegroundColor Yellow
            Invoke-InjectJob -Job $resp.inject_job
        }`;

if (s.includes('inject_jobs -and')) {
  console.log('ALREADY PATCHED: inject_jobs array handling');
} else if (s.includes('# Check for inject job in heartbeat response')) {
  s = s.replace(oldHeartbeatCheck, newHeartbeatCheck);
  console.log('PATCHED: Heartbeat inject_jobs array handling');
} else {
  console.log('WARN: Could not find heartbeat inject_job check block');
}

// === PATCH 4: Update Invoke-InjectJob to use enhanced fields ===
const oldInvokeStart = `    $deviceId = $Job.device_id
    $payload = $Job.payload
    $payloadType = $Job.payload_type
    $jobId = $Job.id`;

const newInvokeStart = `    $deviceId = $Job.device_id
    $payload = $Job.payload
    $payloadType = $Job.payload_type
    $jobId = if ($Job.job_id) { $Job.job_id } else { $Job.id }
    $targetType = $Job.target_device_type
    $targetDrive = $Job.target_drive
    $targetPath = $Job.payload_path`;

if (s.includes('$targetType = $Job.target_device_type')) {
  console.log('ALREADY PATCHED: Invoke-InjectJob enhanced fields');
} else if (s.includes(oldInvokeStart)) {
  s = s.replace(oldInvokeStart, newInvokeStart);
  console.log('PATCHED: Invoke-InjectJob enhanced fields');
} else {
  console.log('WARN: Could not find Invoke-InjectJob start block');
}

// === PATCH 5: Update Invoke-InjectJob to use payload_path when available ===
const oldDuckyWrite = `        if ($payloadType -eq "duckyscript") {
            $ducky = $connected | Where-Object { $_.type -eq "usb_rubber_ducky" }
            if ($ducky) {
                $drive = $ducky[0].drive
                # Save DuckyScript source for reference
                $payload | Out-File "$drive\\payload.txt" -Encoding UTF8`;

const newDuckyWrite = `        if ($payloadType -eq "duckyscript") {
            $ducky = $connected | Where-Object { $_.type -eq "usb_rubber_ducky" }
            # Use server-provided drive/path if available
            if ($targetDrive) { $dDrive = $targetDrive } elseif ($ducky) { $dDrive = $ducky[0].drive } else { $dDrive = $null }
            if ($dDrive) {
                $drive = $dDrive
                # Save DuckyScript source for reference
                $payload | Out-File "$drive\\payload.txt" -Encoding UTF8`;

if (s.includes('# Use server-provided drive/path if available')) {
  console.log('ALREADY PATCHED: Server-provided drive');
} else if (s.includes(oldDuckyWrite)) {
  s = s.replace(oldDuckyWrite, newDuckyWrite);
  console.log('PATCHED: DuckyScript server-provided drive');
} else {
  console.log('WARN: Could not find DuckyScript write block');
}

fs.writeFileSync(f, s);
console.log('PATCHED: ' + f);
console.log('Restart server to serve updated agent via /api/agent/download.');
