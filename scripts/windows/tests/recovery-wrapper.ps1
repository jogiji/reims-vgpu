#Requires -Version 7.2
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Wrapper)
$ErrorActionPreference = 'Stop'
$sourceScripts = Split-Path $PSScriptRoot
$environmentScript = Join-Path $sourceScripts 'environment.ps1'
$wrapper = [IO.Path]::GetFullPath($Wrapper)
$testRoot = Join-Path (Split-Path (Split-Path $PSScriptRoot)) ('.work/tmp/recovery-wrapper-test-' + [guid]::NewGuid().ToString('N'))
$oldProject = $env:REIMS_PROJECT_ROOT_OVERRIDE
$oldVm = $env:REIMS_VM_ROOT_OVERRIDE
$env:REIMS_PROJECT_ROOT_OVERRIDE = $testRoot
Remove-Item Env:REIMS_VM_ROOT_OVERRIDE -ErrorAction SilentlyContinue
. $environmentScript
. (Join-Path $sourceScripts 'start.ps1') -FunctionsOnly
$assertions = 0
function Assert-Condition([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw "ASSERT: $Message" }
    $script:assertions++
}
try {
    $first = & (Join-Path $sourceScripts 'prepare-vm.ps1') -Iso $wrapper -RecoveryWrapper -InspectOnly -HashIso | ConvertFrom-Json
    Assert-Condition ($first.recovery_wrapper -eq $true -and $first.media_kind -eq 'disk' -and $first.container -eq 'GPT/FAT32') 'Explicit recovery mode validates a GPT/FAT32 payload as a disk'
    Assert-Condition ($first.files.'com.apple.recovery.boot/basesystem.dmg'.sha256 -eq 'EDDDD0D5869CAAA12E29E6996A04F11590280580976A119DBD42C24FA62FE18E') 'Inspector verifies the pinned Apple DMG bytes inside the wrapper'
    Assert-Condition ($first.sha256 -eq (Get-FileHash -LiteralPath $wrapper -Algorithm SHA256).Hash) 'InspectOnly records the whole wrapper digest'

    $config = [pscustomobject]@{
        schema = 1; cpus = 8; memory_mib = 8192; resolution = '1920x1080'; disk_gib = 128
        cpu = 'Haswell-noTSX,enforce'; mac = '52:54:00:01:02:03'; qmp_port = 4444; ssh_port = 2222
        iso = $wrapper; media_kind = 'disk'; base_disk = Join-Path $testRoot 'vm/disks/base.qcow2'
        active_disk = Join-Path $testRoot 'vm/disks/current.qcow2'; opencore = Join-Path $testRoot 'vm/firmware/opencore.img'
        firmware_code = Join-Path $testRoot 'vm/firmware/code.fd'; firmware_vars = Join-Path $testRoot 'vm/firmware/vars.fd'
        rom = Join-Path $testRoot 'vm/firmware/ReimsVgpu.rom'
    }
    $arguments = Get-ReimsQemuArguments $config $testRoot
    Assert-Condition (($arguments | Where-Object { $_ -like 'id=installer,*' }) -match '^id=installer,if=none,format=raw,snapshot=on,file=') 'Recovery wrapper uses the raw snapshot-backed installer drive'
    Assert-Condition ('ide-hd,bus=sata.4,drive=installer' -in $arguments) 'Recovery wrapper stays on the existing SATA 4 IDE disk attachment'
    $config.media_kind = 'cdrom'
    $cdrom = Get-ReimsQemuArguments $config $testRoot
    Assert-Condition (($cdrom | Where-Object { $_ -like 'id=installer,*' }) -match 'media=cdrom,readonly=on' -and 'ide-cd,bus=sata.4,drive=installer' -in $cdrom) 'Existing ISO installer remains a read-only SATA 4 CD'

    $second = & (Join-Path $sourceScripts 'prepare-vm.ps1') -Iso $wrapper -RecoveryWrapper -InspectOnly -HashIso | ConvertFrom-Json
    Assert-Condition ($second.sha256 -eq $first.sha256 -and $second.files.Count -eq $first.files.Count) 'Repeated offline inspection is idempotent'
    [pscustomobject]@{ assertions = $assertions; passed = $true; vm_boot = $false; wrapper = $wrapper } | ConvertTo-Json
} finally {
    $env:REIMS_PROJECT_ROOT_OVERRIDE = $oldProject
    if ($null -ne $oldVm) { $env:REIMS_VM_ROOT_OVERRIDE = $oldVm }
    $root = [IO.Path]::GetFullPath($testRoot)
    $tempRoot = [IO.Path]::GetFullPath((Join-Path (Split-Path (Split-Path $PSScriptRoot)) '.work/tmp')) + [IO.Path]::DirectorySeparatorChar
    if ($root.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $root)) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
