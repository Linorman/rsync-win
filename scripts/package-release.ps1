param(
    [Parameter(Mandatory = $true)]
    [string]$Tag,

    [string]$Target = "x86_64-pc-windows-msvc",

    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $Tag.StartsWith("v")) {
    throw "Release tag must start with v, got '$Tag'."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$distDir = Join-Path $repoRoot "dist"
$packageDir = Join-Path $distDir "package"
$assetName = "rsync-win-$Tag-$Target.zip"
$assetPath = Join-Path $distDir $assetName
$checksumPath = "$assetPath.sha256"
$binaryPath = Join-Path $repoRoot "target\$Target\release\rsync-win.exe"

if (-not $SkipBuild) {
    Push-Location $repoRoot
    try {
        cargo build --release -p rsync-cli --target $Target
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path $binaryPath)) {
    throw "Release binary not found at '$binaryPath'. Run without -SkipBuild or build it first."
}

New-Item -ItemType Directory -Force -Path $distDir | Out-Null
if (Test-Path $packageDir) {
    Remove-Item -LiteralPath $packageDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $packageDir | Out-Null

Copy-Item $binaryPath (Join-Path $packageDir "rsync-win.exe")
Copy-Item (Join-Path $repoRoot "README.md") (Join-Path $packageDir "README.md")
Copy-Item (Join-Path $repoRoot "LICENSE") (Join-Path $packageDir "LICENSE")
Copy-Item (Join-Path $repoRoot "LICENSE-MIT") (Join-Path $packageDir "LICENSE-MIT")
Copy-Item (Join-Path $repoRoot "LICENSE-APACHE") (Join-Path $packageDir "LICENSE-APACHE")
Copy-Item (Join-Path $repoRoot "THIRD-PARTY-NOTICES.md") (Join-Path $packageDir "THIRD-PARTY-NOTICES.md")
New-Item -ItemType Directory -Force -Path (Join-Path $packageDir "docs") | Out-Null
Copy-Item (Join-Path $repoRoot "docs\COMPATIBILITY.md") (Join-Path $packageDir "docs\COMPATIBILITY.md")

if (Test-Path $assetPath) {
    Remove-Item -LiteralPath $assetPath -Force
}
if (Test-Path $checksumPath) {
    Remove-Item -LiteralPath $checksumPath -Force
}

Compress-Archive -Path (Join-Path $packageDir "*") -DestinationPath $assetPath -Force
$hash = Get-FileHash $assetPath -Algorithm SHA256
"$($hash.Hash.ToLowerInvariant())  $assetName" | Set-Content $checksumPath -Encoding utf8

Write-Output "Created $assetPath"
Write-Output "Created $checksumPath"
