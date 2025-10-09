#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build script for GhidraMCP extension
.DESCRIPTION
    Downloads Ghidra if needed, extracts required JARs, and builds the extension with Maven.
.PARAMETER Keep
    Keep the downloaded Ghidra installation after extracting JARs (default: delete)
.PARAMETER SkipTests
    Skip running tests during Maven build
.EXAMPLE
    .\build.ps1
    .\build.ps1 -Keep
    .\build.ps1 -SkipTests
#>

param(
    [switch]$Keep,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

Write-Host "=== GhidraMCP Build Script ===" -ForegroundColor Cyan
Write-Host ""

# Required Ghidra libraries
$GHIDRA_LIBS = @(
    "Features/Base/lib/Base.jar",
    "Features/Decompiler/lib/Decompiler.jar",
    "Features/MicrosoftCodeAnalyzer/lib/MicrosoftCodeAnalyzer.jar",
    "Features/MicrosoftDemangler/lib/MicrosoftDemangler.jar",
    "Features/MicrosoftDmang/lib/MicrosoftDmang.jar",
    "Framework/Docking/lib/Docking.jar",
    "Framework/Generic/lib/Generic.jar",
    "Framework/Project/lib/Project.jar",
    "Framework/SoftwareModeling/lib/SoftwareModeling.jar",
    "Framework/Utility/lib/Utility.jar",
    "Framework/Gui/lib/Gui.jar"
)

# Extract Ghidra version and date from pom.xml
Write-Host "Extracting Ghidra version from pom.xml..." -ForegroundColor Yellow
$GHIDRA_VERSION = mvn help:evaluate -Dexpression=ghidra.version -q -DforceStdout
$GHIDRA_DATE = mvn help:evaluate -Dexpression=ghidra.release.date -q -DforceStdout

if ([string]::IsNullOrWhiteSpace($GHIDRA_VERSION) -or [string]::IsNullOrWhiteSpace($GHIDRA_DATE)) {
    Write-Host "❌ Failed to extract Ghidra version from pom.xml" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Ghidra Version: $GHIDRA_VERSION" -ForegroundColor Green
Write-Host "✅ Ghidra Date: $GHIDRA_DATE" -ForegroundColor Green
Write-Host ""

# Check if lib directory has all required JARs
$LIB_DIR = "lib"
$NEEDS_DOWNLOAD = $false

Write-Host "Checking for required Ghidra JARs in $LIB_DIR..." -ForegroundColor Yellow

if (-not (Test-Path $LIB_DIR)) {
    Write-Host "⚠️  lib/ directory does not exist" -ForegroundColor Yellow
    $NEEDS_DOWNLOAD = $true
}
else {
    foreach ($libPath in $GHIDRA_LIBS) {
        $jarName = Split-Path $libPath -Leaf
        $localJar = Join-Path $LIB_DIR $jarName
        
        if (-not (Test-Path $localJar)) {
            Write-Host "⚠️  Missing: $jarName" -ForegroundColor Yellow
            $NEEDS_DOWNLOAD = $true
            break
        }
    }
    
    if (-not $NEEDS_DOWNLOAD) {
        Write-Host "✅ All required JARs found in lib/" -ForegroundColor Green
    }
}
Write-Host ""

# Download and extract Ghidra if needed
if ($NEEDS_DOWNLOAD) {
    Write-Host "Downloading Ghidra $GHIDRA_VERSION..." -ForegroundColor Yellow
    
    $GHIDRA_URL = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"
    $GHIDRA_ZIP = "ghidra.zip"
    $TEMP_DIR = "tmp"
    
    # Download Ghidra
    Write-Host "Downloading from: $GHIDRA_URL" -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $GHIDRA_URL -OutFile $GHIDRA_ZIP -UseBasicParsing
        Write-Host "✅ Download complete" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Failed to download Ghidra: $_" -ForegroundColor Red
        exit 1
    }
    Write-Host ""
    
    # Extract Ghidra
    Write-Host "Extracting Ghidra..." -ForegroundColor Yellow
    if (-not (Test-Path $TEMP_DIR)) {
        New-Item -ItemType Directory -Path $TEMP_DIR | Out-Null
    }
    
    try {
        Expand-Archive -Path $GHIDRA_ZIP -DestinationPath $TEMP_DIR -Force
        Write-Host "✅ Extraction complete" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Failed to extract Ghidra: $_" -ForegroundColor Red
        exit 1
    }
    Write-Host ""
    
    # Find the extracted Ghidra directory
    $GHIDRA_DIR = Get-ChildItem -Path $TEMP_DIR -Filter "ghidra_*_PUBLIC" -Directory | Select-Object -First 1
    if (-not $GHIDRA_DIR) {
        Write-Host "❌ Could not find extracted Ghidra directory in $TEMP_DIR" -ForegroundColor Red
        exit 1
    }
    
    $GHIDRA_ROOT = Join-Path $GHIDRA_DIR.FullName "Ghidra"
    Write-Host "Ghidra root: $GHIDRA_ROOT" -ForegroundColor Cyan
    Write-Host ""
    
    # Create lib directory if it doesn't exist
    if (-not (Test-Path $LIB_DIR)) {
        New-Item -ItemType Directory -Path $LIB_DIR | Out-Null
    }
    
    # Copy required JARs
    Write-Host "Copying required JARs to lib/..." -ForegroundColor Yellow
    foreach ($libPath in $GHIDRA_LIBS) {
        $sourceJar = Join-Path $GHIDRA_ROOT $libPath
        $jarName = Split-Path $libPath -Leaf
        $destJar = Join-Path $LIB_DIR $jarName
        
        if (Test-Path $sourceJar) {
            Copy-Item -Path $sourceJar -Destination $destJar -Force
            Write-Host "  ✅ Copied: $jarName" -ForegroundColor Green
        }
        else {
            Write-Host "  ❌ Not found: $libPath" -ForegroundColor Red
        }
    }
    Write-Host ""
    
    # Cleanup
    Write-Host "Cleaning up..." -ForegroundColor Yellow
    Remove-Item -Path $GHIDRA_ZIP -Force -ErrorAction SilentlyContinue
    
    if (-not $Keep) {
        Remove-Item -Path $TEMP_DIR -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "✅ Removed temporary Ghidra files" -ForegroundColor Green
    }
    else {
        Write-Host "✅ Kept Ghidra installation in $TEMP_DIR (--Keep flag)" -ForegroundColor Green
    }
    Write-Host ""
}

# Build with Maven
Write-Host "Building with Maven..." -ForegroundColor Yellow
$mvnArgs = @("clean", "package")

if ($SkipTests) {
    $mvnArgs += "-DskipTests"
    Write-Host "⚠️  Skipping tests" -ForegroundColor Yellow
}
else {
    $mvnArgs += "-P", "ci-tests"
}

Write-Host "Running: mvn $($mvnArgs -join ' ')" -ForegroundColor Cyan
Write-Host ""

try {
    & mvn $mvnArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Maven build failed with exit code $LASTEXITCODE"
    }
}
catch {
    Write-Host ""
    Write-Host "❌ Build failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Build artifacts:" -ForegroundColor Cyan
Get-ChildItem -Path "target" -Filter "*.jar" | ForEach-Object {
    Write-Host "  📦 $($_.Name) ($([math]::Round($_.Length / 1MB, 2)) MB)" -ForegroundColor White
}
Get-ChildItem -Path "target" -Filter "*.zip" | ForEach-Object {
    Write-Host "  📦 $($_.Name) ($([math]::Round($_.Length / 1MB, 2)) MB)" -ForegroundColor White
}
Write-Host ""

