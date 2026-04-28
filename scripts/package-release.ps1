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
$releaseNotesTemplate = Join-Path $repoRoot "docs\RELEASE-NOTES-TEMPLATE.md"

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
Copy-Item $releaseNotesTemplate (Join-Path $packageDir "docs\RELEASE-NOTES-TEMPLATE.md")

$expectedPackageFiles = @(
    "rsync-win.exe",
    "README.md",
    "LICENSE",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "THIRD-PARTY-NOTICES.md",
    "docs\COMPATIBILITY.md",
    "docs\RELEASE-NOTES-TEMPLATE.md"
)

foreach ($relativePath in $expectedPackageFiles) {
    $candidate = Join-Path $packageDir $relativePath
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Release package staging is missing '$relativePath'."
    }
}

if (Test-Path $assetPath) {
    Remove-Item -LiteralPath $assetPath -Force
}
if (Test-Path $checksumPath) {
    Remove-Item -LiteralPath $checksumPath -Force
}

Compress-Archive -Path (Join-Path $packageDir "*") -DestinationPath $assetPath -Force

$packagedBinary = Join-Path $packageDir "rsync-win.exe"
$versionOutput = & $packagedBinary --version 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Packaged rsync-win.exe --version failed with exit code $LASTEXITCODE`: $($versionOutput -join "`n")"
}
if (($versionOutput -join "`n") -notmatch "rsync-win") {
    throw "Packaged rsync-win.exe --version output did not identify rsync-win: $($versionOutput -join "`n")"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($assetPath)
try {
    $zipEntries = @($zip.Entries | ForEach-Object { $_.FullName })
} finally {
    $zip.Dispose()
}

foreach ($relativePath in $expectedPackageFiles) {
    $zipPath = $relativePath.Replace("\", "/")
    if ($zipEntries -notcontains $zipPath) {
        throw "Release zip is missing '$zipPath'."
    }
}

$hash = Get-FileHash $assetPath -Algorithm SHA256
"$($hash.Hash.ToLowerInvariant())  $assetName" | Set-Content $checksumPath -Encoding utf8
$checksumText = (Get-Content $checksumPath -Raw).Trim()
$checksumPattern = "^[0-9a-f]{64}  $([regex]::Escape($assetName))$"
if ($checksumText -notmatch $checksumPattern) {
    throw "Checksum file has unexpected format: '$checksumText'."
}

Write-Output "Created $assetPath"
Write-Output "Created $checksumPath"
Write-Output "Verified package contents and rsync-win.exe --version"
