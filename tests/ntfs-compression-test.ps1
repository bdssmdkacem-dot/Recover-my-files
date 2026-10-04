[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Prepare","Verify")]
    [string]$Mode,

    [Parameter(Mandatory=$true)]
    [string]$Root,

    [string]$RecoveredFile
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Root)) {
    New-Item -ItemType Directory -Force -Path $Root | Out-Null
}

$rootFull = (Resolve-Path $Root).Path
$sourceFile = Join-Path $rootFull "ntfs-compression-test.bin"
$manifest = Join-Path $rootFull "ntfs-compression-test.sha256"

function New-TestPayload {
    param([string]$Path)

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buffer = New-Object byte[] (1024 * 1024)

    try {
        $stream = [System.IO.File]::Create($Path)
        try {
            # 256 MiB deterministic-ish mixed payload:
            # highly compressible blocks plus incompressible blocks.
            for ($block = 0; $block -lt 256; $block++) {
                if (($block % 8) -lt 6) {
                    [Array]::Fill($buffer, [byte](($block * 17) % 251))
                    for ($i = 0; $i -lt $buffer.Length; $i += 4096) {
                        $buffer[$i] = [byte](($block + $i) % 251)
                    }
                } else {
                    $rng.GetBytes($buffer)
                }
                $stream.Write($buffer, 0, $buffer.Length)
            }
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $rng.Dispose()
    }
}

if ($Mode -eq "Prepare") {
    if (-not (Get-Volume -FilePath $rootFull -ErrorAction SilentlyContinue)) {
        Write-Warning "Make sure Root is on an NTFS volume before continuing."
    }

    if (Test-Path $sourceFile) {
        Remove-Item -Force $sourceFile
    }

    Write-Host "Creating 256 MiB test file: $sourceFile"
    New-TestPayload -Path $sourceFile

    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceFile).Hash
    "$hash  $sourceFile" | Set-Content -Encoding ASCII $manifest

    Write-Host "Enabling NTFS compression..."
    & compact.exe /c /q "$sourceFile"
    if ($LASTEXITCODE -ne 0) {
        throw "compact.exe failed with exit code $LASTEXITCODE"
    }

    Write-Host ""
    Write-Host "=== TEST INPUT READY ===" -ForegroundColor Green
    Write-Host "Source:   $sourceFile"
    Write-Host "Manifest: $manifest"
    Write-Host "SHA-256:  $hash"
    Write-Host ""
    Write-Host "Next:"
    Write-Host "  1. Confirm compact.exe reports the file as compressed."
    Write-Host "  2. Delete the source file."
    Write-Host "  3. Run Recovery.exe as Administrator."
    Write-Host "  4. Quick Scan the NTFS volume."
    Write-Host "  5. Confirm the result is marked 'Compressed'."
    Write-Host "  6. Recover it to another drive/folder."
    Write-Host "  7. Run this script again with -Mode Verify and -RecoveredFile <path>."
    exit 0
}

if (-not $RecoveredFile) {
    throw "-RecoveredFile is required in Verify mode."
}

if (-not (Test-Path -LiteralPath $RecoveredFile -PathType Leaf)) {
    throw "Recovered file does not exist: $RecoveredFile"
}

$expectedHash = (Get-Content -LiteralPath $manifest -Raw).Trim().Split()[0]
$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $RecoveredFile).Hash

$expectedLength = 256MB
$actualLength = (Get-Item -LiteralPath $RecoveredFile).Length

Write-Host "Expected size: $expectedLength"
Write-Host "Actual size:   $actualLength"
Write-Host "Expected SHA:  $expectedHash"
Write-Host "Actual SHA:    $actualHash"

if ($actualLength -ne $expectedLength) {
    throw "FAIL: recovered file size differs."
}

if ($actualHash -ne $expectedHash) {
    throw "FAIL: recovered bytes differ (SHA-256 mismatch)."
}

Write-Host ""
Write-Host "PASS: NTFS compressed recovery is byte-for-byte identical." -ForegroundColor Green
