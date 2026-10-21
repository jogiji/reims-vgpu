#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RecoveryRoot,
    [Parameter(Mandatory)][string]$Dmg,
    [Parameter(Mandatory)][string]$Chunklist,
    [Parameter(Mandatory)][string]$Macrecovery,
    [Parameter(Mandatory)][string]$OpenCoreZip,
    [string]$SevenZip,
    [string]$Python
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/start.ps1" -FunctionsOnly
$RecoveryRoot = [IO.Path]::GetFullPath($RecoveryRoot)
$Dmg = [IO.Path]::GetFullPath($Dmg)
$Chunklist = [IO.Path]::GetFullPath($Chunklist)
$Macrecovery = [IO.Path]::GetFullPath($Macrecovery)
$OpenCoreZip = [IO.Path]::GetFullPath($OpenCoreZip)
$free = (Get-PSDrive -Name $RecoveryRoot.Substring(0, 1)).Free
if ($free -lt 200GB) { throw 'Recovery preparation requires at least 200 GiB free on the output drive.' }
foreach ($path in @($Dmg, $Chunklist, $Macrecovery, $OpenCoreZip)) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required verified input is missing: $path" }
}
$helper = Join-Path $PSScriptRoot 'recovery_media.py'
$Python = Get-ReimsTool 'python.exe' $Python
$SevenZip = Get-ReimsTool '7z.exe' $SevenZip
$stage = Join-Path $RecoveryRoot ('.stage1g1-' + [guid]::NewGuid().ToString('N'))
$image = Join-Path $RecoveryRoot 'media/Recovery-wrapper.raw'
New-Item -ItemType Directory -Force -Path $stage, (Split-Path $image) | Out-Null
try {
    $verifyOutput = @(& $Python $helper verify-chunklist --dmg $Dmg --chunklist $Chunklist --macrecovery $Macrecovery)
    if ($LASTEXITCODE -ne 0) { throw 'OpenCore macrecovery signed chunklist/image verification failed.' }
    $verify = ($verifyOutput | Where-Object { $_ -match '^\{"chunk_count"' } | Select-Object -Last 1) | ConvertFrom-Json
    if (!$verify -or $verify.chunk_count -ne 92) { throw 'The pinned Tahoe Recovery chunklist did not verify as the expected 92 chunks.' }

    $payloadStage = Join-Path $stage 'payload'
    New-Item -ItemType Directory -Force -Path $payloadStage | Out-Null
    $dmgListing = Invoke-ReimsTool $SevenZip @('l', '-slt', $Dmg)
    $dmgPaths = @($dmgListing | Where-Object { $_ -like 'Path = *' } | ForEach-Object { $_.Substring(7) })
    $versionPath = $dmgPaths | Where-Object { $_.Replace([string][char]92, '/') -match '(^|/)System/Library/CoreServices/SystemVersion\.plist$' } | Select-Object -First 1
    $booterPath = $dmgPaths | Where-Object { $_.Replace([string][char]92, '/') -match '(^|/)usr/standalone/i386/boot\.efi$' } | Select-Object -First 1
    if (!$versionPath -or !$booterPath) { throw 'Nested BaseSystem.dmg lacks its version plist or standalone x86_64 booter.' }
    Invoke-ReimsTool $SevenZip @('e', '-y', "-o$payloadStage", $Dmg, $versionPath, $booterPath) | Out-Null
    $payloadOutput = @(& $Python $helper validate-payload --version-plist (Join-Path $payloadStage 'SystemVersion.plist') --booter (Join-Path $payloadStage 'boot.efi'))
    if ($LASTEXITCODE -ne 0) { throw 'Nested Recovery version/standalone booter validation failed.' }
    $payload = ($payloadOutput | Select-Object -Last 1) | ConvertFrom-Json

    Invoke-ReimsTool $SevenZip @('x', '-y', "-o$stage", $OpenCoreZip, 'X64/EFI/BOOT/BOOTx64.efi') | Out-Null
    $bootx64 = Join-Path $stage 'X64/EFI/BOOT/BOOTx64.efi'
    if (!(Test-Path -LiteralPath $bootx64 -PathType Leaf)) { throw 'OpenCore 1.0.8 X64 EFI fallback loader was not extracted.' }
    if (Test-Path -LiteralPath $image) {
        $buildOutput = @(& $Python $helper inspect --image $image)
    } else {
        $buildOutput = @(& $Python $helper build --output $image --dmg $Dmg --chunklist $Chunklist --bootx64 $bootx64)
    }
    if ($LASTEXITCODE -ne 0) { throw 'File-backed GPT/FAT32 Recovery wrapper validation/build failed.' }
    $wrapper = ($buildOutput | Select-Object -Last 1) | ConvertFrom-Json
    if ($wrapper.container -ne 'GPT/FAT32' -or $wrapper.media_kind -ne 'disk') { throw 'Generated wrapper did not validate as a GPT/FAT32 disk.' }

    $evidence = [ordered]@{
        schema = 1
        status = 'PASS'
        product_version = $payload.product_version
        product_build = $payload.product_build
        recovery_boot_architecture = $payload.boot_architecture
        recovery_boot_bytes = $payload.boot_bytes
        recovery_boot_sha256 = $payload.boot_sha256
        apple_chunk_count = $verify.chunk_count
        base_system_sha256 = $verify.dmg_sha256
        chunklist_sha256 = $verify.chunklist_sha256
        wrapper = $wrapper.path
        wrapper_bytes = $wrapper.bytes
        wrapper_sha256 = (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash
        files = $wrapper.files
    }
    $evidencePath = Join-Path $RecoveryRoot 'media/wrapper-validation.json'
    $rootPrefix = $RecoveryRoot.TrimEnd([char[]]@('\','/')) + [IO.Path]::DirectorySeparatorChar
    if (![IO.Path]::GetFullPath($evidencePath).StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Recovery evidence must stay inside the selected Recovery workspace.'
    }
    [IO.File]::WriteAllText($evidencePath, ($evidence | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    if ((Get-PSDrive -Name $RecoveryRoot.Substring(0, 1)).Free -lt 200GB) { throw 'Recovery preparation would violate the 200 GiB free-space reserve.' }
    $evidence | ConvertTo-Json -Depth 6
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
