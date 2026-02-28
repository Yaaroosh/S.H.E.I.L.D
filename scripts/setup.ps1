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
function Download-And-ExtractZip {
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
function Verify-Tool {
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
# Install Nuclei (pinned)
# -------------------------
function Install-Nuclei {
    $NucleiDir = Join-Path $ToolsDir "nuclei"
    $NucleiExe = Join-Path $NucleiDir $Lock.nuclei.exe

    if (Test-Path $NucleiExe) {
        Write-Host "Nuclei already installed." -ForegroundColor Green
        & $NucleiExe -version
        return
    }

    $tag   = $Lock.nuclei.tag
    $asset = $Lock.nuclei.asset

    $url = "https://github.com/projectdiscovery/nuclei/releases/download/$tag/$asset"
    $zip = Join-Path $ToolsDir $asset

    Download-And-ExtractZip -Url $url -ZipPath $zip -DestDir $NucleiDir

    # Verify installation
    $NucleiExe = Join-Path $NucleiDir $Lock.nuclei.exe
    Verify-Tool -Name "Nuclei" -ExecutablePath $NucleiExe -VersionArgs "-version"
    Write-Host "Nuclei installed successfully." -ForegroundColor Green
    & $NucleiExe -version
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

    Download-And-ExtractZip -Url $url -ZipPath $zip -DestDir $ZapDir

    # Verify installation
    $zapBat = Get-ChildItem -Path $ZapDir -Recurse -Filter $Lock.zap.entry_bat -ErrorAction SilentlyContinue | Select-Object -First 1

    $zapPath = if ($zapBat) { $zapBat.FullName } else { "" }

    Verify-Tool -Name "OWASP ZAP" -ExecutablePath $zapPath
    Write-Host "ZAP installed: $($zapBat.FullName)" -ForegroundColor Green
    Write-Host "Reminder: ZAP requires Java 17+ to run." -ForegroundColor Cyan
}

# -------------------------
# Install OWASP Juice Shop
# -------------------------
function Install-JuiceShop {
    $JuiceShopDir = Join-Path $ToolsDir "juice-shop"

    if (Test-Path $JuiceShopDir) {
        $packageJson = Join-Path $JuiceShopDir "package.json"
        $nodeModules = Join-Path $JuiceShopDir "node_modules"
        $builtServer = Join-Path $JuiceShopDir "build\app"
        $dockerMarker = Join-Path $JuiceShopDir 'INSTALLED_VIA_DOCKER'
        
        # check for docker-based installation first
        if (Test-Path $dockerMarker) {
            Write-Host "OWASP Juice Shop marked as installed via Docker." -ForegroundColor Green
            return
        }

        # consider the install valid only if dependencies and the build output exist
        if ((Test-Path $packageJson) -and (Test-Path $nodeModules) -and (Test-Path $builtServer)) {
            Write-Host "OWASP Juice Shop already installed and built." -ForegroundColor Green
            return
        }
        else {
            # Incomplete or broken installation, remove and retry
            Write-Host "Removing incomplete or broken Juice Shop installation..." -ForegroundColor Yellow
            Remove-Item -Path $JuiceShopDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Check for Node.js
    try {
        $nodeVersion = & node --version 2>$null
        Write-Host "Found Node.js: $nodeVersion" -ForegroundColor Green
        if ($nodeVersion -match '^v(\d+)') {
            $nodeMajor = [int]$matches[1]
        } else {
            $nodeMajor = 0
        }
    }
    catch {
        $nodeVersion = $null
        $nodeMajor = 0
        Write-Host "Node.js is required to run OWASP Juice Shop but was not found." -ForegroundColor Red
    }

    if (-not $nodeVersion) {
        Write-Host "Please install Node.js 18+ (recommended v20 for best compatibility) from https://nodejs.org/" -ForegroundColor Yellow
        return
    }

    if ($nodeMajor -gt 20) {
        Write-Host "Detected Node.js v$nodeMajor which may not be able to build Juice Shop." -ForegroundColor Yellow
        if (Get-Command docker -ErrorAction SilentlyContinue) {
            Write-Host "Docker is available; you may prefer to use the container instead of building." -ForegroundColor Cyan
            Write-Host "The script will still attempt the source install unless you manually interrupt." -ForegroundColor Cyan
            # optionally pull image for later
            $imageTag = $Lock.juice_shop.tag.TrimStart('v')
            & docker pull "bkimminich/juice-shop:$imageTag" | Out-Null
            Write-Host "If build fails you can run the pulled container: docker run -p 3000:3000 bkimminich/juice-shop:$imageTag" -ForegroundColor Green
        }
        else {
            Write-Host "Continuing with a source build despite unsupported Node version." -ForegroundColor Yellow
        }
        # do not return; proceed with clone and install
    }

    # Check for Git
    try {
        $gitVersion = & git --version 2>$null
        Write-Host "Found Git: $gitVersion" -ForegroundColor Green
    }
    catch {
        Write-Host "Git is required to clone OWASP Juice Shop but was not found." -ForegroundColor Red
        Write-Host "Please install Git from https://git-scm.com/" -ForegroundColor Yellow
        return
    }

    $repo = $Lock.juice_shop.repo
    $tag  = $Lock.juice_shop.tag

    Write-Host "Cloning OWASP Juice Shop from GitHub..." -ForegroundColor Yellow
    & git clone --depth 1 --branch $tag "https://github.com/$repo.git" $JuiceShopDir
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to clone Juice Shop repository." -ForegroundColor Red
        exit 1
    }

    # Install npm dependencies
    Write-Host "Installing npm dependencies for Juice Shop..." -ForegroundColor Cyan
    Push-Location $JuiceShopDir
    try {
        & npm install --legacy-peer-deps
        if ($LASTEXITCODE -ne 0) {
            Write-Host "npm install failed for Juice Shop." -ForegroundColor Red
            Pop-Location
            exit 1
        }
    }
    finally {
        Pop-Location
    }

    Write-Host "OWASP Juice Shop installed successfully." -ForegroundColor Green
    Write-Host "To run Juice Shop: npm start" -ForegroundColor Cyan
    Write-Host "Then visit: http://localhost:3000" -ForegroundColor Cyan
}

Install-Nuclei
Install-Zap
Install-JuiceShop

Write-Host "Setup complete." -ForegroundColor Green