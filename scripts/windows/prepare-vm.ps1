#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$Iso,
    [string]$SevenZip,
    [string]$QemuImg,
    [switch]$InspectOnly,
    [switch]$HashIso,
    [switch]$RecoveryWrapper,
    [ValidateRange(64,2048)][int]$DiskGiB = 128,
    [ValidateRange(1024, 65535)][int]$QmpPort = 4444,
    [ValidateRange(1024, 65535)][int]$SshPort = 2222
)
. "$PSScriptRoot/start.ps1" -FunctionsOnly
Assert-ReimsVmStopped
if ($QmpPort -eq $SshPort) { throw 'QMP and SSH must use different ports.' }
$state = Join-Path $VmRoot 'state'
$mediaState = Join-Path $state 'media.json'
if (!$Iso -and (Test-Path -LiteralPath $mediaState)) {
    $Iso = (Get-Content -Raw -LiteralPath $mediaState | ConvertFrom-Json).path
}
if (!$Iso) { throw 'Pass -Iso with your installer image; its path is remembered in vm/state/media.json.' }
$mediaFile = Get-Item -LiteralPath $Iso -ErrorAction Stop
$Iso = $mediaFile.FullName
$length = $mediaFile.Length
$modified = $mediaFile.LastWriteTimeUtc.Ticks
$SevenZip = Get-ReimsTool '7z.exe' $SevenZip
$python = Get-ReimsTool 'python.exe'
$inspection = Join-Path $VmRoot 'media/inspection'
New-Item -ItemType Directory -Force -Path $inspection, $state | Out-Null
if ($RecoveryWrapper) {
    $helper = Join-Path $PSScriptRoot 'recovery_media.py'
    $json = & $python $helper inspect --image $Iso
    if ($LASTEXITCODE -ne 0) { throw 'Recovery wrapper GPT/FAT32 contents/hash validation failed.' }
    $media = $json | ConvertFrom-Json -AsHashtable
    $media.recovery_wrapper = $true
} else {
$listing = Invoke-ReimsTool $SevenZip @('l', '-slt', $Iso)
$listing | Set-Content -LiteralPath (Join-Path $inspection 'contents.txt') -Encoding utf8NoBOM
$paths = @($listing | Where-Object { $_ -like 'Path = *' } | ForEach-Object { $_.Substring(7) })
$versionPath = $paths | Where-Object { $_.Replace('\', '/') -match '(^|/)System/Library/CoreServices/SystemVersion\.plist$' } | Select-Object -First 1
$bootPath = $paths | Where-Object { $_.Replace('\', '/') -match '(^|/)System/Library/CoreServices/boot\.efi$' } | Select-Object -First 1
if (!$versionPath -or !$bootPath) { throw 'No installer SystemVersion.plist and boot.efi found; media has not been prepared.' }
# Extract only the two small inspection files; never expand the installer payload.
Invoke-ReimsTool $SevenZip @('e', '-y', "-o$inspection", $Iso, $versionPath, $bootPath) | Out-Null
$script = @'
import json, pathlib, plistlib, struct, sys
image, folder = map(pathlib.Path, sys.argv[1:3])
with image.open('rb') as f:
    header = f.read(1024)
    f.seek(16 * 2048)
    iso9660 = f.read(7)[1:6] == b'CD001'
if header[:2] == b'ER' and header[512:514] == b'PM':
    kind, container = 'disk', 'APM/HFS+'
elif iso9660:
    kind, container = 'cdrom', 'ISO9660'
else:
    raise SystemExit('Unsupported media header; refusing to infer format from extension.')
version = plistlib.loads((folder / 'SystemVersion.plist').read_bytes())
b = (folder / 'boot.efi').read_bytes()
if b[:2] != b'MZ' or len(b) < 64:
    raise SystemExit('boot.efi is not a PE image.')
off = struct.unpack_from('<I', b, 0x3c)[0]
if b[off:off+4] != b'PE\0\0' or struct.unpack_from('<H', b, off+4)[0] != 0x8664:
    raise SystemExit('Installer boot.efi is not x86_64.')
print(json.dumps({'schema':1, 'path':str(image), 'bytes':image.stat().st_size,
    'container':container, 'media_kind':kind, 'boot_architecture':'x86_64',
    'product_version':version['ProductVersion'], 'product_build':version['ProductBuildVersion']}))
'@
$json = $script | & $python - $Iso $inspection
if ($LASTEXITCODE -ne 0) { throw 'Installer header/version/architecture validation failed.' }
$media = $json | ConvertFrom-Json -AsHashtable
}
$media.last_write_ticks = $modified
if ($HashIso) { $media.sha256 = (Get-FileHash -LiteralPath $Iso -Algorithm SHA256).Hash }
elseif (Test-Path -LiteralPath $mediaState) {
    $old = Get-Content -Raw -LiteralPath $mediaState | ConvertFrom-Json -AsHashtable
    if ($old.path -eq $Iso -and $old.bytes -eq $length -and $old.last_write_ticks -eq $modified -and $old.ContainsKey('sha256')) { $media.sha256 = $old.sha256 }
}
$mediaFile.Refresh()
if ($mediaFile.Length -ne $length -or $mediaFile.LastWriteTimeUtc.Ticks -ne $modified) { throw 'Installer changed during inspection.' }
Write-ReimsJson $mediaState $media
if ($InspectOnly) { $media | ConvertTo-Json; return }
$opencorePath = Join-Path $state 'opencore.json'
if (!(Test-Path -LiteralPath $opencorePath)) { throw 'Run prepare-opencore.ps1 first. ISO inspection has been saved.' }
$oc = Get-Content -Raw -LiteralPath $opencorePath | ConvertFrom-Json
foreach ($file in @($oc.image, $oc.firmware_code, $oc.firmware_vars_template)) {
    [void](Assert-ReimsArtifactPath $file)
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing prepared firmware: $file" }
}
$QemuImg = Get-ReimsTool 'qemu-img.exe' $QemuImg
$configPath = Join-Path $state 'config.json'
if (Test-Path -LiteralPath $configPath) {
    $config = Get-ReimsVmConfig
    $config.iso = $Iso
    $config.media_kind = $media.media_kind
    Write-ReimsJson $configPath $config
    'Existing disks, NVRAM and VM settings retained; installer inspection updated.'
    return
}
$disks = Join-Path $VmRoot 'disks'
New-Item -ItemType Directory -Force -Path $disks | Out-Null
$baseDisk = Join-Path $disks 'base.qcow2'
$activeDisk = Join-Path $disks 'current.qcow2'
if (!(Test-Path -LiteralPath $baseDisk)) { Invoke-ReimsTool $QemuImg @('create', '-f', 'qcow2', $baseDisk, "$($DiskGiB)G") | Out-Null }
$info = (Invoke-ReimsTool $QemuImg @('info', '--output=json', $baseDisk)) -join "`n" | ConvertFrom-Json
if ($info.format -ne 'qcow2' -or $info.'virtual-size' -ne [long]$DiskGiB * 1GB -or $info.PSObject.Properties['backing-filename']) { throw "Existing base disk is not an independent $DiskGiB GiB qcow2 image." }
if (!(Test-Path -LiteralPath $activeDisk)) {
    Invoke-ReimsTool $QemuImg @('create', '-f', 'qcow2', '-F', 'qcow2', '-b', $baseDisk, $activeDisk) | Out-Null
}
$activeInfo = (Invoke-ReimsTool $QemuImg @('info', '--output=json', $activeDisk)) -join "`n" | ConvertFrom-Json
if ($activeInfo.format -ne 'qcow2' -or !$activeInfo.PSObject.Properties['full-backing-filename'] -or
    [IO.Path]::GetFullPath($activeInfo.'full-backing-filename') -ne $baseDisk) {
    throw 'Existing current disk is not an overlay of this base disk.'
}
$vars = Join-Path $VmRoot 'firmware/OVMF_VARS.fd'
if (!(Test-Path -LiteralPath $vars)) { Copy-Item -LiteralPath $oc.firmware_vars_template -Destination $vars }
$random = [Security.Cryptography.RandomNumberGenerator]::GetBytes(3)
$config = [ordered]@{
    schema = 1; cpus = 8; memory_mib = 8192; resolution = '1920x1080'; disk_gib = $DiskGiB
    cpu = 'Haswell-noTSX,stepping=3,vendor=GenuineIntel,+ssse3,+sse4.2,+popcnt,+avx,+avx2,+aes,+xsave,+xsaveopt,-arat,enforce'
    mac = '52:54:00:' + (($random | ForEach-Object { $_.ToString('x2') }) -join ':')
    qmp_port = $QmpPort; ssh_port = $SshPort; iso = $Iso; media_kind = $media.media_kind
    base_disk = $baseDisk; active_disk = $activeDisk; opencore = $oc.image
    firmware_code = $oc.firmware_code; firmware_vars = $vars
    rom = Join-Path $ProjectRoot '.work/target/dist-vulkan/share/reims-vgpu/ReimsVgpu.rom'
}
Write-ReimsJson $configPath $config
$config | ConvertTo-Json -Depth 5
