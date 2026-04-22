Write-Host "Setting up S.H.E.I.L.D tools..." -ForegroundColor Cyan


$ErrorActionPreference = "Stop"

# -------------------------
# Paths
# -------------------------
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ToolsDir    = Join-Path $ProjectRoot "tools"
$LockPath    = Join-Path $ProjectRoot "tools.lock.json"

if (!(Test-Path $ToolsDir)) { New-Item -ItemType Directory -Path $ToolsDir | Out-Null }
if (!(Test-Path $LockPath)) { throw "Missing tools.lock.json at: $LockPath" }

$Lock = Get-Content -Raw -Path $LockPath | ConvertFrom-Json
# -------------------------
# Helpers
# -------------------------
function Invoke-DownloadAndExtractZip {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$ZipPath,
        [Parameter(Mandatory=$true)][string]$DestDir
    )
    Write-Host "Downloading: $Url" -ForegroundColor Yellow
    Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing

    if (!(Test-Path $DestDir)) { New-Item -ItemType Directory -Path $DestDir | Out-Null }
    Expand-Archive -Path $ZipPath -DestinationPath $DestDir -Force
    Remove-Item $ZipPath -Force
}
function Test-Tool {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$ExecutablePath,
        [string]$VersionArgs = ""
    )

    if (!(Test-Path $ExecutablePath)) {
        Write-Host "$Name installation failed. Executable not found at $ExecutablePath" -ForegroundColor Red
        exit 1
    }

    Write-Host "Verifying $Name..." -ForegroundColor Cyan

    if ($VersionArgs -ne "") {
        & $ExecutablePath $VersionArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host "$Name exists but failed to execute." -ForegroundColor Red
            exit 1
        }
    }

    Write-Host "$Name verified successfully." -ForegroundColor Green
}

# -------------------------
# Install CodeQL CLI (pinned)
# -------------------------
function Install-CodeQL {
    $CodeQLDir = Join-Path $ToolsDir "codeql"
    $CodeQLExe = Join-Path $CodeQLDir $Lock.codeql.entry_exe

    if (Test-Path $CodeQLExe) {
        Write-Host "CodeQL already installed." -ForegroundColor Green
        & $CodeQLExe version
        return
    }

    $repo  = $Lock.codeql.repo
    $tag   = $Lock.codeql.tag
    $asset = $Lock.codeql.asset

    $url = "https://github.com/$repo/releases/download/$tag/$asset"
    $zip = Join-Path $ToolsDir $asset

    Invoke-DownloadAndExtractZip -Url $url -ZipPath $zip -DestDir $CodeQLDir

    $CodeQLExe = Join-Path $CodeQLDir $Lock.codeql.entry_exe
    Test-Tool -Name "CodeQL" -ExecutablePath $CodeQLExe -VersionArgs "version"
    Write-Host "CodeQL installed successfully." -ForegroundColor Green
}

# -------------------------
# Install OWASP ZAP (pinned)
# -------------------------
function Install-Zap {
    $ZapDir = Join-Path $ToolsDir "zap"

    # ZAP zip extracts into a versioned folder, so we search for zap.bat anywhere under tools\zap
    $existing = Get-ChildItem -Path $ZapDir -Recurse -Filter $Lock.zap.entry_bat -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existing) {
        Write-Host "ZAP already installed: $($existing.FullName)" -ForegroundColor Green
        return
    }

    $repo  = $Lock.zap.repo
    $tag   = $Lock.zap.tag
    $asset = $Lock.zap.asset

    $url = "https://github.com/$repo/releases/download/$tag/$asset"
    $zip = Join-Path $ToolsDir $asset

    Invoke-DownloadAndExtractZip -Url $url -ZipPath $zip -DestDir $ZapDir

    # Verify installation
    $zapBat = Get-ChildItem -Path $ZapDir -Recurse -Filter $Lock.zap.entry_bat -ErrorAction SilentlyContinue | Select-Object -First 1

    $zapPath = if ($zapBat) { $zapBat.FullName } else { "" }

    Test-Tool -Name "OWASP ZAP" -ExecutablePath $zapPath
    Write-Host "ZAP installed: $($zapBat.FullName)" -ForegroundColor Green
    Write-Host "Reminder: ZAP requires Java 17+ to run." -ForegroundColor Cyan
}

# -------------------------
# Install ffuf (pinned)
# -------------------------
function Install-Ffuf {
    $FfufDir = Join-Path $ToolsDir "ffuf"
    $FfufExe = Join-Path $FfufDir $Lock.ffuf.entry_exe
    $DefaultWordlist = Join-Path $FfufDir $Lock.ffuf.default_wordlist_path

    if ((Test-Path $FfufExe) -and (Test-Path $DefaultWordlist)) {
        Write-Host "ffuf already installed." -ForegroundColor Green
        & $FfufExe -h | Out-Null
        return
    }

    $repo  = $Lock.ffuf.repo
    $tag   = $Lock.ffuf.tag
    $asset = $Lock.ffuf.asset

    $url = "https://github.com/$repo/releases/download/$tag/$asset"
    $zip = Join-Path $ToolsDir $asset

    Invoke-DownloadAndExtractZip -Url $url -ZipPath $zip -DestDir $FfufDir

    $FfufExe = Join-Path $FfufDir $Lock.ffuf.entry_exe
    if (!(Test-Path $FfufExe)) {
        $found = Get-ChildItem -Path $FfufDir -Recurse -Filter $Lock.ffuf.entry_exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            $FfufExe = $found.FullName
        }
    }

    Test-Tool -Name "ffuf" -ExecutablePath $FfufExe -VersionArgs "-h"

    $WordlistUrl = $Lock.ffuf.default_wordlist_url
    $WordlistDir = Split-Path -Parent $DefaultWordlist
    if (!(Test-Path $WordlistDir)) {
        New-Item -ItemType Directory -Path $WordlistDir -Force | Out-Null
    }
    Write-Host "Downloading ffuf default wordlist..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri $WordlistUrl -OutFile $DefaultWordlist -UseBasicParsing
    if (!(Test-Path $DefaultWordlist)) {
        Write-Host "ffuf default wordlist installation failed at $DefaultWordlist" -ForegroundColor Red
        exit 1
    }

    Write-Host "ffuf installed successfully." -ForegroundColor Green
}

Install-CodeQL
Install-Zap
Install-Ffuf

Write-Host "Setup complete." -ForegroundColor Green