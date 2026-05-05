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
$optionStatus = Join-Path $repoRoot "docs\OPTION-STATUS.md"

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
Copy-Item $optionStatus (Join-Path $packageDir "docs\OPTION-STATUS.md")
Copy-Item $releaseNotesTemplate (Join-Path $packageDir "docs\RELEASE-NOTES-TEMPLATE.md")

$expectedPackageFiles = @(
    "rsync-win.exe",
    "README.md",
    "LICENSE",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "THIRD-PARTY-NOTICES.md",
    "docs\COMPATIBILITY.md",
    "docs\OPTION-STATUS.md",
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

$helpOutput = & $packagedBinary --help 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Packaged rsync-win.exe --help failed with exit code $LASTEXITCODE`: $($helpOutput -join "`n")"
}
if (($helpOutput -join "`n") -notmatch "--archive") {
    throw "Packaged rsync-win.exe --help output did not include rsync options: $($helpOutput -join "`n")"
}

$smokeRoot = Join-Path $packageDir "package-smoke"
$smokeSource = Join-Path $smokeRoot "source"
$smokeDest = Join-Path $smokeRoot "dest"
if (Test-Path -LiteralPath $smokeRoot) {
    Remove-Item -LiteralPath $smokeRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path (Join-Path $smokeSource "dir") | Out-Null
Set-Content -Path (Join-Path $smokeSource "dir\file.txt") -Value "package smoke" -NoNewline -Encoding utf8
$syncOutput = & $packagedBinary -rt $smokeSource $smokeDest 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Packaged rsync-win.exe local sync smoke failed with exit code $LASTEXITCODE`: $($syncOutput -join "`n")"
}
$smokeFile = Join-Path $smokeDest "dir\file.txt"
if (-not (Test-Path -LiteralPath $smokeFile -PathType Leaf)) {
    throw "Packaged rsync-win.exe local sync smoke did not create '$smokeFile'. Output: $($syncOutput -join "`n")"
}
if ((Get-Content -Raw $smokeFile) -ne "package smoke") {
    throw "Packaged rsync-win.exe local sync smoke copied unexpected file contents."
}

$filterSource = Join-Path $smokeRoot "filter-source"
$filterDest = Join-Path $smokeRoot "filter-dest"
New-Item -ItemType Directory -Force -Path $filterSource | Out-Null
New-Item -ItemType Directory -Force -Path $filterDest | Out-Null
Set-Content -Path (Join-Path $filterSource "keep.txt") -Value "keep" -NoNewline -Encoding utf8
Set-Content -Path (Join-Path $filterSource "skip.tmp") -Value "source-excluded" -NoNewline -Encoding utf8
Set-Content -Path (Join-Path $filterDest "stale.txt") -Value "delete-me" -NoNewline -Encoding utf8
Set-Content -Path (Join-Path $filterDest "skip.tmp") -Value "receiver-protected" -NoNewline -Encoding utf8
$filterOutput = & $packagedBinary -rt --delete "--exclude=*.tmp" $filterSource $filterDest 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Packaged rsync-win.exe local delete/filter smoke failed with exit code $LASTEXITCODE`: $($filterOutput -join "`n")"
}
if ((Get-Content -Raw (Join-Path $filterDest "keep.txt")) -ne "keep") {
    throw "Packaged rsync-win.exe local delete/filter smoke did not copy keep.txt."
}
if (Test-Path -LiteralPath (Join-Path $filterDest "stale.txt")) {
    throw "Packaged rsync-win.exe local delete/filter smoke did not delete stale.txt."
}
if ((Get-Content -Raw (Join-Path $filterDest "skip.tmp")) -ne "receiver-protected") {
    throw "Packaged rsync-win.exe local delete/filter smoke did not protect excluded receiver file."
}

function Invoke-PackageSsh {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Command
    )

    $sshOutput = & ssh -o BatchMode=yes -o ConnectTimeout=10 $Target $Command 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Package SSH smoke command failed with exit code $LASTEXITCODE`: $Command`n$($sshOutput -join "`n")"
    }
    return $sshOutput
}

$sshTarget = $env:RSYNC_WIN_SSH_TARGET
if (-not [string]::IsNullOrWhiteSpace($sshTarget)) {
    $sshTmpRoot = if ([string]::IsNullOrWhiteSpace($env:RSYNC_WIN_SSH_TMP_ROOT)) {
        "/tmp"
    } else {
        $env:RSYNC_WIN_SSH_TMP_ROOT.TrimEnd("/")
    }
    if ($sshTmpRoot -notmatch "^/[A-Za-z0-9._/-]+$") {
        throw "RSYNC_WIN_SSH_TMP_ROOT must be an absolute POSIX path without shell-special characters for package SSH smoke, got '$sshTmpRoot'."
    }
    $remoteRoot = "$sshTmpRoot/rsync-win-package-$PID-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
    $sshSource = Join-Path $smokeRoot "ssh-source"
    $sshPullDest = Join-Path $smokeRoot "ssh-pull"
    New-Item -ItemType Directory -Force -Path (Join-Path $sshSource "dir") | Out-Null
    New-Item -ItemType Directory -Force -Path $sshPullDest | Out-Null
    Set-Content -Path (Join-Path $sshSource "dir\file.txt") -Value "package ssh smoke" -NoNewline -Encoding utf8

    try {
        Invoke-PackageSsh $sshTarget "rm -rf $remoteRoot; mkdir -p $remoteRoot/dest" | Out-Null
        $sshCommand = "ssh -o BatchMode=yes -o ConnectTimeout=10"
        $sshPushOutput = & $packagedBinary -rt --whole-file -e $sshCommand $sshSource "${sshTarget}:$remoteRoot/dest/" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Packaged rsync-win.exe optional SSH smoke push failed with exit code $LASTEXITCODE`: $($sshPushOutput -join "`n")"
        }
        Invoke-PackageSsh $sshTarget "test -s $remoteRoot/dest/dir/file.txt" | Out-Null
        $sshPullOutput = & $packagedBinary -rt --whole-file -e $sshCommand "${sshTarget}:$remoteRoot/dest/" $sshPullDest 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Packaged rsync-win.exe optional SSH smoke pull failed with exit code $LASTEXITCODE`: $($sshPullOutput -join "`n")"
        }
        if ((Get-Content -Raw (Join-Path $sshPullDest "dir\file.txt")) -ne "package ssh smoke") {
            throw "Packaged rsync-win.exe optional SSH smoke pulled unexpected file contents."
        }
    } finally {
        try {
            Invoke-PackageSsh $sshTarget "rm -rf $remoteRoot" | Out-Null
        } catch {
            Write-Warning "Failed to clean optional SSH smoke directory '$remoteRoot': $_"
        }
    }
}

$daemonUrl = $env:RSYNC_WIN_DAEMON_URL
if (-not [string]::IsNullOrWhiteSpace($daemonUrl)) {
    $daemonBase = $daemonUrl.TrimEnd("/")
    $daemonListOutput = & $packagedBinary --list-only "$daemonBase/" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Packaged rsync-win.exe daemon module list smoke failed with exit code $LASTEXITCODE`: $($daemonListOutput -join "`n")"
    }
    if (($daemonListOutput -join "`n") -notmatch "rsync-win daemon module list") {
        throw "Packaged rsync-win.exe daemon module list smoke returned unexpected output: $($daemonListOutput -join "`n")"
    }

    $daemonModule = $env:RSYNC_WIN_DAEMON_MODULE
    $daemonPath = $env:RSYNC_WIN_DAEMON_PATH
    if (-not [string]::IsNullOrWhiteSpace($daemonModule) -and -not [string]::IsNullOrWhiteSpace($daemonPath)) {
        $daemonDest = Join-Path $smokeRoot "daemon-pull"
        $daemonSource = "$daemonBase/$($daemonModule.Trim('/'))/$($daemonPath.TrimStart('/'))"
        $daemonPullOutput = & $packagedBinary -r --whole-file $daemonSource $daemonDest 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Packaged rsync-win.exe daemon pull smoke failed with exit code $LASTEXITCODE`: $($daemonPullOutput -join "`n")"
        }
    }

    $daemonUser = $env:RSYNC_WIN_DAEMON_USER
    $daemonPasswordFile = $env:RSYNC_WIN_DAEMON_PASSWORD_FILE
    $daemonAuthModule = if ([string]::IsNullOrWhiteSpace($env:RSYNC_WIN_DAEMON_AUTH_MODULE)) { $daemonModule } else { $env:RSYNC_WIN_DAEMON_AUTH_MODULE }
    $daemonAuthPath = if ([string]::IsNullOrWhiteSpace($env:RSYNC_WIN_DAEMON_AUTH_PATH)) { $daemonPath } else { $env:RSYNC_WIN_DAEMON_AUTH_PATH }
    if (-not [string]::IsNullOrWhiteSpace($daemonAuthModule) -and
        -not [string]::IsNullOrWhiteSpace($daemonAuthPath) -and
        -not [string]::IsNullOrWhiteSpace($daemonUser) -and
        -not [string]::IsNullOrWhiteSpace($daemonPasswordFile)) {
        $authBase = if ($daemonBase.StartsWith("rsync://")) {
            "rsync://$daemonUser@$($daemonBase.Substring("rsync://".Length))"
        } else {
            "$daemonUser@$daemonBase"
        }
        $authDest = Join-Path $smokeRoot "daemon-auth-pull"
        $authSource = "$authBase/$($daemonAuthModule.Trim('/'))/$($daemonAuthPath.TrimStart('/'))"
        $daemonAuthOutput = & $packagedBinary -r --whole-file --password-file $daemonPasswordFile $authSource $authDest 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Packaged rsync-win.exe daemon auth pull smoke failed with exit code $LASTEXITCODE`: $($daemonAuthOutput -join "`n")"
        }
    }
}
Remove-Item -LiteralPath $smokeRoot -Recurse -Force

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($assetPath)
try {
    $zipEntries = @($zip.Entries | ForEach-Object { $_.FullName.Replace("\", "/") })
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
Write-Output "Verified package contents, rsync-win.exe --version, --help, local sync smoke, local delete/filter smoke, optional SSH smoke, and optional daemon smoke"
