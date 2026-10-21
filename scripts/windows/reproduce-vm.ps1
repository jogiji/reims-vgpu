#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PinnedSourceRoot,
    [Parameter(Mandatory)][string]$WorkspaceRoot,
    [Parameter(Mandatory)][string]$VmRoot,
    [ValidateSet('Fresh', 'Restore')][string]$Mode = 'Fresh',
    [string]$InputsRoot,
    [string]$CheckpointRoot,
    [ValidateRange(200, 4096)][int]$MinimumFreeGiB = 200,
    [switch]$DryRun,
    [switch]$FunctionsOnly
)

$ErrorActionPreference = 'Stop'
$script:ReimsProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:ReimsPinsPath = Join-Path $script:ReimsProjectRoot 'docs/windows-vm-pins.json'
$script:ReimsProtectedRoots = @('D:\reims-vgpu-windows', 'D:\ReimsVM\Tahoe-Recovery-26', $script:ReimsProjectRoot)

function ConvertTo-ReimsFullPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or ![IO.Path]::IsPathRooted($Path)) {
        throw "Path must be absolute: $Path"
    }
    if (($Path -split '[\\/]') -contains '..') { throw "Path traversal is not allowed: $Path" }
    return [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
}

function Test-ReimsPathOverlaps([string]$Left, [string]$Right) {
    $a = ConvertTo-ReimsFullPath $Left
    $b = ConvertTo-ReimsFullPath $Right
    $aPrefix = $a + [IO.Path]::DirectorySeparatorChar
    $bPrefix = $b + [IO.Path]::DirectorySeparatorChar
    return $a.Equals($b, [StringComparison]::OrdinalIgnoreCase) -or
        $a.StartsWith($bPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $b.StartsWith($aPrefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-ReimsNoReparsePath([string]$Path) {
    $full = ConvertTo-ReimsFullPath $Path
    $root = [IO.Path]::GetPathRoot($full)
    $cursor = $full
    while ($cursor -and $cursor.TrimEnd('\', '/') -ne $root.TrimEnd('\', '/')) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse-point paths are not allowed: $cursor"
            }
        }
        $parent = Split-Path -Parent $cursor
        if (!$parent -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Invoke-ReimsQemuImg([string]$QemuImg, [string[]]$Arguments) {
    $oldPath = $env:PATH
    $msysRoot = if ($env:REIMS_MSYS2_ROOT) { $env:REIMS_MSYS2_ROOT } else { 'D:\msys64' }
    $env:PATH = (@((Split-Path -Parent $QemuImg), (Join-Path $msysRoot 'ucrt64/bin'),
        (Join-Path $msysRoot 'usr/bin'), $oldPath) -join [IO.Path]::PathSeparator)
    try { & $QemuImg @Arguments }
    finally { $env:PATH = $oldPath }
}

function Assert-ReimsFreshDestination([string]$Workspace, [string]$Destination) {
    $workspacePath = ConvertTo-ReimsFullPath $Workspace
    $destinationPath = ConvertTo-ReimsFullPath $Destination
    if ($workspacePath -eq [IO.Path]::GetPathRoot($workspacePath).TrimEnd('\','/')) { throw 'Workspace cannot be a drive root.' }
    if ($destinationPath -eq $workspacePath) { throw 'VM destination must be a child of the explicit workspace.' }
    $prefix = $workspacePath + [IO.Path]::DirectorySeparatorChar
    if (!$destinationPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'VM destination must remain under the explicit workspace.'
    }
    foreach ($protected in $script:ReimsProtectedRoots) {
        if (Test-ReimsPathOverlaps $destinationPath $protected) {
            throw "VM destination overlaps protected existing data: $protected"
        }
    }
    Assert-ReimsNoReparsePath $workspacePath
    Assert-ReimsNoReparsePath $destinationPath
    if (Test-Path -LiteralPath $destinationPath) {
        $item = Get-Item -LiteralPath $destinationPath -Force
        if (!$item.PSIsContainer) { throw 'VM destination exists as a file.' }
        if (@(Get-ChildItem -LiteralPath $destinationPath -Force).Count -ne 0) {
            throw 'VM destination must be empty; existing files are never overwritten.'
        }
    }
    if (Test-Path -LiteralPath $workspacePath -PathType Leaf) { throw 'Workspace root is a file.' }
    return [pscustomobject]@{ workspace = $workspacePath; vm = $destinationPath }
}

function Get-ReimsPinnedSourceState([string]$ScriptsRoot, [string]$PinnedSourceRoot, $Pins) {
    $scriptsHead = $null
    $scriptsBranch = $null
    $sourceHead = $null
    $qemuGitlink = $null
    $trackedChanges = $null
    $cargoLockPin = $null
    $scriptBaseAncestor = $false
    if (Get-Command git -CommandType Application -ErrorAction SilentlyContinue) {
        $headOutput = & git -C $ScriptsRoot rev-parse HEAD 2>$null
        if ($LASTEXITCODE -eq 0) { $scriptsHead = [string]($headOutput | Select-Object -First 1) }
        $scriptsBranch = [string](& git -C $ScriptsRoot branch --show-current 2>$null | Select-Object -First 1)
        $sourceOutput = & git -C $PinnedSourceRoot rev-parse HEAD 2>$null
        if ($LASTEXITCODE -eq 0) { $sourceHead = [string]($sourceOutput | Select-Object -First 1) }
        $treeLine = (& git -C $PinnedSourceRoot ls-tree HEAD vendor/qemu 2>$null | Select-Object -First 1)
        if ($treeLine -match '^160000 commit ([a-f0-9]{40})\s+vendor/qemu$') { $qemuGitlink = $Matches[1] }
        $status = @(& git -C $ScriptsRoot status --porcelain --untracked-files=no 2>$null)
        $trackedChanges = @($status).Count
    }
    $cargoLock = Join-Path $PinnedSourceRoot 'Cargo.lock'
    if (Test-Path -LiteralPath $cargoLock) {
        $lockText = Get-Content -LiteralPath $cargoLock -Raw
        $cargoLockPin = $lockText.Contains($Pins.metal2vulkan_commit)
    }
    $reimsAncestor = $false
    if ($scriptsHead) {
        & git -C $ScriptsRoot merge-base --is-ancestor $Pins.scripts_commit HEAD 2>$null
        $scriptBaseAncestor = ($LASTEXITCODE -eq 0)
    }
    $reimsExact = ($sourceHead -eq $Pins.reims_commit)
    [pscustomobject]@{
        scripts_branch = $scriptsBranch
        scripts_head = $scriptsHead
        source_head = $sourceHead
        expected_reviewed_scripts_commit = $Pins.scripts_commit
        expected_reims_commit = $Pins.reims_commit
        expected_qemu_submodule_commit = $Pins.qemu_submodule_commit
        actual_qemu_submodule_gitlink = $qemuGitlink
        metal2vulkan_pin_in_cargo_lock = $cargoLockPin
        tracked_worktree_change_count = $trackedChanges
        qemu_pin_matches = ($qemuGitlink -eq $Pins.qemu_submodule_commit)
        scripts_base_is_ancestor = $scriptBaseAncestor
        reims_commit_matches = $reimsExact
    }
}

function Get-ReimsArtifactAudit([string]$Root, $Manifest, [string]$Mode) {
    $base = ConvertTo-ReimsFullPath $Root
    $rows = @()
    foreach ($artifactSpec in $Manifest.inputs) {
        $relative = [string]$artifactSpec.path
        if ([IO.Path]::IsPathRooted($relative) -or ($relative -split '[\\/]') -contains '..') {
            throw "Unsafe input path in pin manifest: $relative"
        }
        $path = [IO.Path]::GetFullPath((Join-Path $base $relative))
        $prefix = $base + [IO.Path]::DirectorySeparatorChar
        if (!$path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Input escapes the supplied root: $relative" }
        Assert-ReimsNoReparsePath $path
        $expected = [string]$Manifest.pins.($artifactSpec.sha256Pin)
        $actual = $null
        $bytes = $null
        $state = 'missing'
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $file = Get-Item -LiteralPath $path
            $bytes = [long]$file.Length
            $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
            $state = if ($actual -eq $expected.ToUpperInvariant()) { 'pass' } else { 'mismatch' }
        }
        $copyEstimateGiB = if ($artifactSpec.PSObject.Properties['estimatedCopyGiB']) { [double]$artifactSpec.estimatedCopyGiB } else { 0.0 }
        $estimate = if ($bytes -ne $null) { [Math]::Max($bytes, [long]($copyEstimateGiB * 1GB)) } else { [long]($copyEstimateGiB * 1GB) }
        $required = @($artifactSpec.requiredFor) -contains $Mode
        $copied = @($artifactSpec.copyInModes) -contains $Mode
        $rows += [pscustomobject]@{
            name = $artifactSpec.name
            path = $path
            expected_sha256 = $expected
            actual_sha256 = $actual
            bytes = $bytes
            status = $state
            required = $required
            copied_to_vm = $copied
            estimated_copy_bytes = if ($copied) { $estimate } else { 0L }
        }
    }
    return $rows
}

function Get-ReimsCheckpointAudit([string]$Root, [string]$QemuImg) {
    $checkpoint = ConvertTo-ReimsFullPath $Root
    if (Test-ReimsPathOverlaps $checkpoint 'D:\ReimsVM\Tahoe-Recovery-26') {
        throw 'A checkpoint under the installed VM root cannot be used as a restore source.'
    }
    Assert-ReimsNoReparsePath $checkpoint
    $qemuOwners = @(Get-CimInstance Win32_Process -Filter "name='qemu-system-x86_64.exe'" -ErrorAction SilentlyContinue)
    if ($qemuOwners.Count) { throw 'Restore dry run requires no QEMU process on the host.' }
    $manifestPath = Join-Path $checkpoint 'reims-checkpoint.json'
    Assert-ReimsNoReparsePath $manifestPath
    if (!(Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return [pscustomobject]@{ status = 'missing_manifest'; manifest = $manifestPath; files = @(); bytes = 0L }
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 1 -or !$manifest.files) { throw 'Unsupported or incomplete checkpoint manifest.' }
    $required = @('current.qcow2', 'base.qcow2', 'OVMF_VARS.fd', 'config.json', 'opencore-identity.json')
    $names = @($manifest.files | ForEach-Object { [string]$_.name })
    foreach ($name in $required) { if ($name -notin $names) { throw "Checkpoint is missing required entry: $name" } }
    $rows = @()
    foreach ($entry in $manifest.files) {
        $name = [string]$entry.name
        if ($name -notin $required) { throw "Unexpected checkpoint file entry: $name" }
        $path = Join-Path $checkpoint $name
        Assert-ReimsNoReparsePath $path
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Checkpoint file is missing: $name" }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($hash -ne ([string]$entry.sha256).ToUpperInvariant()) { throw "Checkpoint hash mismatch: $name" }
        $file = Get-Item -LiteralPath $path
        if ($entry.bytes -and [long]$entry.bytes -ne $file.Length) { throw "Checkpoint size mismatch: $name" }
        $rows += [pscustomobject]@{ name = $name; sha256 = $hash; bytes = [long]$file.Length; status = 'pass' }
    }
    $overlayEntry = $manifest.files | Where-Object name -EQ 'current.qcow2' | Select-Object -First 1
    $baseEntry = $manifest.files | Where-Object name -EQ 'base.qcow2' | Select-Object -First 1
    if ($overlayEntry.backingFile -ne 'base.qcow2' -or $baseEntry.backingFile) {
        throw 'Checkpoint manifest does not preserve the current overlay -> base.qcow2 relationship.'
    }
    $config = Get-Content -LiteralPath (Join-Path $checkpoint 'config.json') -Raw | ConvertFrom-Json
    if ((Split-Path ([string]$config.active_disk) -Leaf) -ne 'current.qcow2' -or
        (Split-Path ([string]$config.base_disk) -Leaf) -ne 'base.qcow2') {
        throw 'Checkpoint config does not identify the manifest overlay and backing image.'
    }
    if (!(Test-Path -LiteralPath $QemuImg -PathType Leaf)) { throw 'Pinned qemu-img is missing for offline QCOW2 verification.' }
    $current = Join-Path $checkpoint 'current.qcow2'
    $base = Join-Path $checkpoint 'base.qcow2'
    $chainOutput = @(Invoke-ReimsQemuImg $QemuImg @('info','--backing-chain','--output=json',$current) 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'qemu-img could not inspect the checkpoint backing chain.' }
    try { $chain = ($chainOutput -join "`n") | ConvertFrom-Json }
    catch { throw 'qemu-img returned invalid JSON for the checkpoint backing chain.' }
    $actualBacking = [string]$chain[0].'backing-filename'
    if (!$actualBacking) { throw 'Checkpoint current.qcow2 has no backing image.' }
    $actualBackingPath = if ([IO.Path]::IsPathRooted($actualBacking)) { [IO.Path]::GetFullPath($actualBacking) } else { [IO.Path]::GetFullPath((Join-Path $checkpoint $actualBacking)) }
    if (!$actualBackingPath.Equals([IO.Path]::GetFullPath($base), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Checkpoint overlay backing path does not resolve to checkpoint base.qcow2.'
    }
    $qcowChecks = @()
    foreach ($image in @($current,$base)) {
        $checkOutput = @(Invoke-ReimsQemuImg $QemuImg @('check','-f','qcow2',$image) 2>&1)
        if ($LASTEXITCODE -ne 0) { throw "Non-repairing qcow2 check failed for $(Split-Path $image -Leaf)." }
        $qcowChecks += [pscustomobject]@{ name = (Split-Path $image -Leaf); status = 'pass'; repair = $false }
    }
    [pscustomobject]@{ status = 'pass'; manifest = $manifestPath; files = $rows; bytes = [long](($rows | Measure-Object bytes -Sum).Sum); backing_file = 'base.qcow2'; qcow2_checks = $qcowChecks }
}

function Get-ReimsHostFacts {
    if ($script:ReimsHostFacts) { return $script:ReimsHostFacts }
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name
    $gpu = @(Get-CimInstance Win32_VideoController | ForEach-Object Name)
    $hypervisor = [bool](Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty HypervisorPresent)
    $whpx = (Get-CimInstance Win32_OptionalFeature -Filter "Name='HypervisorPlatform'" | Select-Object -First 1 -ExpandProperty InstallState) -eq 1
    $script:ReimsHostFacts = [pscustomobject]@{ os = $os.Caption; cpu = $cpu; gpu = $gpu; hypervisor_present = $hypervisor; whpx_feature_enabled = [bool]$whpx }
    return $script:ReimsHostFacts
}

function Get-ReimsReproPlan {
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$PinnedSourceRoot,
        [Parameter(Mandatory)][string]$InputsRoot,
        [Parameter(Mandatory)][string]$WorkspaceRoot,
        [Parameter(Mandatory)][string]$VmRoot,
        [Parameter(Mandatory)][ValidateSet('Fresh','Restore')][string]$Mode,
        [string]$CheckpointRoot,
        [Parameter(Mandatory)][int]$MinimumFreeGiB,
        [Parameter(Mandatory)][string]$PinsPath
    )
    $project = ConvertTo-ReimsFullPath $ProjectRoot
    $inputs = ConvertTo-ReimsFullPath $InputsRoot
    if (Test-ReimsPathOverlaps $inputs 'D:\ReimsVM\Tahoe-Recovery-26') {
        throw 'Live installed VM paths cannot be used as artifact inputs.'
    }
    $paths = Assert-ReimsFreshDestination $WorkspaceRoot $VmRoot
    $manifest = Get-Content -LiteralPath $PinsPath -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 1) { throw 'Unsupported pin manifest schema.' }
    $source = Get-ReimsPinnedSourceState $project $PinnedSourceRoot $manifest.pins
    $artifacts = @(Get-ReimsArtifactAudit $inputs $manifest $Mode)
    $problems = [Collections.Generic.List[string]]::new()
    if (!$source.qemu_pin_matches) { $problems.Add('QEMU submodule gitlink does not match the approved pin.') }
    if (!$source.scripts_base_is_ancestor) { $problems.Add('Reviewed Windows scripts commit is not an ancestor of this checkout.') }
    if (!$source.reims_commit_matches) { $problems.Add('Pinned Reims source checkout HEAD does not match the approved revision.') }
    if ($source.metal2vulkan_pin_in_cargo_lock -ne $true) { $problems.Add('Pinned metal2vulkan revision was not found in Cargo.lock.') }
    foreach ($artifact in $artifacts | Where-Object required) {
        if ($artifact.status -eq 'missing') { $problems.Add("Missing pinned input: $($artifact.name)") }
        elseif ($artifact.status -eq 'mismatch') { $problems.Add("SHA-256 mismatch for pinned input: $($artifact.name)") }
    }
    $checkpoint = $null
    if ($Mode -eq 'Restore') {
        if (!$CheckpointRoot) { $problems.Add('Restore mode requires an explicit verified checkpoint root.') }
        else {
            try {
                $qemuImgArtifact = $artifacts | Where-Object name -EQ 'qemu_img' | Select-Object -First 1
                $checkpoint = Get-ReimsCheckpointAudit $CheckpointRoot $qemuImgArtifact.path
            }
            catch { $problems.Add($_.Exception.Message) }
            if ($checkpoint -and $checkpoint.status -ne 'pass') { $problems.Add('Restore checkpoint has no complete reims-checkpoint.json manifest.') }
        }
    } elseif ($CheckpointRoot) { $problems.Add('CheckpointRoot is only valid in Restore mode.') }

    $drive = [IO.Path]::GetPathRoot($paths.vm).Substring(0,1)
    $driveInfo = Get-PSDrive -Name $drive -ErrorAction Stop
    $freeBytes = [long]$driveInfo.Free
    $minBytes = [long]$MinimumFreeGiB * 1GB
    $copyBytes = [long](($artifacts | Measure-Object estimated_copy_bytes -Sum).Sum)
    $guestGrowth = if ($Mode -eq 'Fresh') { [long]$manifest.vm.estimated_guest_growth_gib * 1GB } else { 0L }
    $working = [long]$manifest.vm.estimated_working_gib * 1GB
    if ($Mode -eq 'Restore' -and $checkpoint) { $copyBytes += [long]$checkpoint.bytes }
    $requiredNewBytes = $copyBytes + $guestGrowth + $working
    $remainingAfterPlan = $freeBytes - $requiredNewBytes
    $spacePass = $remainingAfterPlan -ge $minBytes
    if (!$spacePass) { $problems.Add("Space reserve would fall below ${MinimumFreeGiB} GiB under the conservative estimate.") }

    $gfxTemplate = [ordered]@{
        driver = 'apple-gfx-pci'; id = 'gfx'; bus = 'pcie.0'; addr = '0x4'; displays = 1
        resolution = [string]$manifest.vm.resolution
        romfile = '<PINNED_REIMS_ROM>'
        'display-modes' = @("$($manifest.vm.resolution)@60", '1280x720@60', '1920x1080@60', '2560x1440@60', '3840x2160@60') | Select-Object -Unique
    }
    $gfxJson = ConvertTo-Json -InputObject $gfxTemplate -Depth 4 -Compress
    $hostFacts = Get-ReimsHostFacts
    $argv = @(
        '-L','<PINNED_SOURCE_ROOT>/vendor/qemu/pc-bios','-name','reims-windows','-machine','q35',
        '-accel',[string]$manifest.vm.accelerator,'-cpu',[string]$manifest.vm.cpu,
        '-smp',"$($manifest.vm.cpus),sockets=1,cores=$($manifest.vm.cpus),threads=1",
        '-m',"$($manifest.vm.memory_mib)M",
        '-global','ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off',
        '-global','ICH9-LPC.disable_s3=1','-global','ICH9-LPC.disable_s4=1',
        '-device','pcie-root-port,bus=pcie.0,addr=0x1,slot=1,x-speed=16,x-width=32',
        '-device','isa-applesmc,osk=<LOCAL_SECRET_REDACTED>','-smbios','type=2',
        '-drive','if=pflash,format=raw,readonly=on,file=<VM_ROOT>/firmware/OVMF_CODE.fd',
        '-drive','if=pflash,format=raw,file=<VM_ROOT>/firmware/OVMF_VARS.fd',
        '-device','ich9-ahci,id=sata,addr=0x2',
        '-drive','id=opencore,if=none,format=raw,snapshot=on,file=<VM_ROOT>/firmware/OpenCore.img',
        '-device','ide-hd,bus=sata.2,drive=opencore,bootindex=1',
        '-drive','id=disk,if=none,format=qcow2,file=<VM_ROOT>/disks/current.qcow2',
        '-device','ide-hd,bus=sata.3,drive=disk,rotation_rate=1',
        '-netdev','user,id=net0,ipv6=off,hostfwd=tcp:127.0.0.1:2222-:22',
        '-device','virtio-net-pci,netdev=net0,id=net0,mac=<FRESH_GUEST_MAC>,addr=0x3',
        '-vga','none','-device',$gfxJson,
        '-device','qemu-xhci,id=xhci,addr=0x5,p2=8,p3=6,conditional-intr-mapping=on',
        '-device','usb-kbd,id=kbd,bus=xhci.0','-device','usb-tablet,id=tablet,bus=xhci.0',
        '-audiodev',"$($manifest.vm.audio),id=snd0,in.voices=0",'-device','usb-audio,id=audio,audiodev=snd0,bus=xhci.0',
        '-drive','id=installer,if=none,format=raw,snapshot=on,file=<VM_ROOT>/media/Recovery-only.raw',
        '-device','ide-hd,bus=sata.4,drive=installer',
        '-display','none','-monitor','none','-serial','file:<VM_ROOT>/logs/serial.log',
        '-qmp','tcp:127.0.0.1:4444,server=on,wait=off','-no-shutdown'
    )
    $outputs = @('state/config.json','state/opencore-identity.json','firmware/OVMF_VARS.fd','firmware/OpenCore.img',
        'media/Recovery-only.raw','disks/base.qcow2','disks/current.qcow2','logs/') | ForEach-Object { Join-Path $paths.vm $_ }
    [pscustomobject]@{
        schema = 1
        status = if ($problems.Count) { 'BLOCKED' } else { 'READY_FOR_LATER_APPROVAL' }
        mode = $Mode
        source = $source
        input_root = $inputs
        inputs = $artifacts
        checkpoint = $checkpoint
        host = [pscustomobject]@{
            os = $hostFacts.os
            cpu = $hostFacts.cpu
            gpu = $hostFacts.gpu
            hypervisor_present = $hostFacts.hypervisor_present
            whpx_feature_enabled = $hostFacts.whpx_feature_enabled
            free_bytes = $freeBytes
            free_gib = [Math]::Round($freeBytes / 1GB, 2)
        }
        destination = $paths
        outputs = $outputs
        estimate = [pscustomobject]@{
            guest_growth_bytes = $guestGrowth
            copied_inputs_and_checkpoint_bytes = $copyBytes
            working_bytes = $working
            new_bytes = $requiredNewBytes
            minimum_free_bytes = $minBytes
            remaining_bytes = $remainingAfterPlan
            reserve_pass = $spacePass
        }
        qemu_argv_template = $argv
        security_and_host_changes = @()
        rollback = @(
            'Dry run makes no changes. Later fresh provisioning must only target the empty VM root and may remove only files created there before the first boot.',
            'Never restore or remove the source checkpoint; retain manifest and hashes for rollback.',
            'After first boot, rollback requires a separately approved offline checkpoint and matching OVMF VARS/identity.'
        )
        stop_points = @(
            'Stop if any source pin or SHA-256 does not match.',
            'Stop if the free-space reserve would fall below the configured minimum.',
            'Stop before online Recovery installation, disk erase, or guest preference changes for a separate approval.',
            'Restore mode stops unless all checkpoint members and hashes verify and no process owns them.'
        )
        vm_started = $false
        files_written = $false
        problems = @($problems)
    }
}

if ($FunctionsOnly) { return }
if (!$DryRun) { throw 'This entry point is dry-run-only. Pass -DryRun; provisioning is not implemented in this review stage.' }
if (!$InputsRoot) { $InputsRoot = $PinnedSourceRoot }
$plan = Get-ReimsReproPlan -ProjectRoot $script:ReimsProjectRoot -PinnedSourceRoot $PinnedSourceRoot -InputsRoot $InputsRoot -WorkspaceRoot $WorkspaceRoot -VmRoot $VmRoot `
    -Mode $Mode -CheckpointRoot $CheckpointRoot -MinimumFreeGiB $MinimumFreeGiB -PinsPath $script:ReimsPinsPath
$plan | ConvertTo-Json -Depth 20
if ($plan.status -eq 'BLOCKED') { exit 2 }
