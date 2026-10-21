#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
$sourceScripts = Split-Path $PSScriptRoot
$scriptPath = Join-Path $sourceScripts 'reproduce-vm.ps1'
$sourceRoot = 'D:\reims-vgpu-windows'
$repoRoot = Split-Path (Split-Path $sourceScripts)
$testRoot = Join-Path 'D:\ReimsVM' ('Issue4-test-' + [guid]::NewGuid().ToString('N'))
$assertions = 0
$skipped = 0

function Assert-Condition([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw "ASSERT: $Message" }
    $script:assertions++
}

function Assert-Throws([scriptblock]$Action, [string]$Pattern, [string]$Message) {
    try { & $Action; throw 'Expected this operation to fail.' }
    catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw "ASSERT: $Message (got '$($_.Exception.Message)')" }
        $script:assertions++
    }
}

New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $pins = Get-Content (Join-Path $repoRoot 'docs/windows-vm-pins.json') -Raw | ConvertFrom-Json
    $workspace = Join-Path $testRoot 'workspace'
    $vmRoot = Join-Path $workspace 'fresh'
    $inputRoot = Join-Path $testRoot 'inputs'
    New-Item -ItemType Directory -Path $workspace, $inputRoot | Out-Null
    $probe = Join-Path $inputRoot 'probe.bin'
    [IO.File]::WriteAllBytes($probe, [byte[]](1,2,3,4))
    $digest = (Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash.ToUpperInvariant()
    $qemuImgFixture = Join-Path $inputRoot 'build/qemu/qemu-img.exe'
    New-Item -ItemType Directory -Force -Path (Split-Path $qemuImgFixture) | Out-Null
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'build/qemu/qemu-img.exe') -Destination $qemuImgFixture
    $pins.pins | Add-Member -NotePropertyName probe_sha256 -NotePropertyValue $digest -Force
    $pins.inputs = @([pscustomobject]@{
        name = 'probe'; path = 'probe.bin'; sha256Pin = 'probe_sha256'
        requiredFor = @('Fresh','Restore'); copyInModes = @(); estimatedCopyGiB = 0
    }, [pscustomobject]@{
        name = 'qemu_img'; path = 'build/qemu/qemu-img.exe'; sha256Pin = 'qemu_img_sha256'
        requiredFor = @('Fresh','Restore'); copyInModes = @(); estimatedCopyGiB = 0
    })
    $pins.vm.estimated_guest_growth_gib = 1
    $pins.vm.estimated_working_gib = 0.1
    $pinsPath = Join-Path $testRoot 'pins.json'
    $pins | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $pinsPath -Encoding utf8NoBOM

    . $scriptPath -PinnedSourceRoot $sourceRoot -WorkspaceRoot $workspace -VmRoot $vmRoot -DryRun -FunctionsOnly
    $common = @{
        ProjectRoot = $repoRoot; PinnedSourceRoot = $sourceRoot; InputsRoot = $inputRoot
        WorkspaceRoot = $workspace; VmRoot = $vmRoot; Mode = 'Fresh'
        MinimumFreeGiB = 200; PinsPath = $pinsPath
    }
    $plan = Get-ReimsReproPlan @common
    Assert-Condition ($plan.status -eq 'READY_FOR_LATER_APPROVAL') 'pinned fresh dry run is ready without execution'
    Assert-Condition (!$plan.vm_started -and !$plan.files_written -and !(Test-Path $vmRoot)) 'dry run creates no VM files and never starts QEMU'
    Assert-Condition (@($plan.outputs | Where-Object { !$_.StartsWith($vmRoot,[StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) 'every planned output stays under the explicit destination'
    Assert-Condition ($plan.inputs[0].status -eq 'pass' -and $plan.inputs[0].actual_sha256 -eq $digest) 'input hash is verified'
    $identityArguments = @($plan.qemu_argv_template | Where-Object { $_ -match 'SerialNumber=|MLB=|SystemSerialNumber=' })
    Assert-Condition ($identityArguments.Count -eq 0) 'private identity is absent from QEMU argv template'
    Assert-Throws { & $scriptPath -PinnedSourceRoot $sourceRoot -WorkspaceRoot $workspace -VmRoot $vmRoot } 'dry-run-only' 'non-dry-run invocation is refused'

    $badPins = $pins | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $badPins.pins.probe_sha256 = ('0' * 64)
    $badPinsPath = Join-Path $testRoot 'bad-pins.json'
    $badPins | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $badPinsPath -Encoding utf8NoBOM
    # Use a copied parameter map so the only changed input is the pin manifest.
    $badArgs = $common.Clone(); $badArgs.PinsPath = $badPinsPath
    $badHash = Get-ReimsReproPlan @badArgs
    Assert-Condition ($badHash.status -eq 'BLOCKED' -and $badHash.inputs[0].status -eq 'mismatch') 'bad SHA fails closed'

    $missingArgs = $common.Clone(); $missingArgs.InputsRoot = Join-Path $testRoot 'missing-inputs'
    New-Item -ItemType Directory -Path $missingArgs.InputsRoot | Out-Null
    $missing = Get-ReimsReproPlan @missingArgs
    Assert-Condition ($missing.status -eq 'BLOCKED' -and $missing.inputs[0].status -eq 'missing') 'missing input fails closed'

    $wrongSourcePins = $pins | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $wrongSourcePins.pins.reims_commit = '0' * 40
    $wrongSourcePath = Join-Path $testRoot 'wrong-source.json'
    $wrongSourcePins | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $wrongSourcePath -Encoding utf8NoBOM
    $wrongSourceArgs = $common.Clone(); $wrongSourceArgs.PinsPath = $wrongSourcePath
    $wrongSource = Get-ReimsReproPlan @wrongSourceArgs
    Assert-Condition (!$wrongSource.source.reims_commit_matches -and $wrongSource.status -eq 'BLOCKED') 'wrong source revision fails closed'

    $spaceArgs = $common.Clone(); $spaceArgs.MinimumFreeGiB = 4096
    $space = Get-ReimsReproPlan @spaceArgs
    Assert-Condition (!$space.estimate.reserve_pass -and $space.status -eq 'BLOCKED') 'space reserve failure blocks the plan'

    Assert-Throws { Assert-ReimsFreshDestination $workspace (Join-Path $testRoot 'outside') } 'under the explicit workspace' 'destination outside workspace is rejected'
    Assert-Throws { ConvertTo-ReimsFullPath (Join-Path $workspace '..\escape') } 'traversal' 'path traversal is rejected'
    Assert-Throws { Assert-ReimsFreshDestination 'D:\' 'D:\unrelated' } 'drive root' 'drive-root workspace is rejected'
    Assert-Throws { Assert-ReimsFreshDestination 'D:\reims-vgpu-windows' 'D:\reims-vgpu-windows\new-vm' } 'overlaps protected' 'source checkout overlap is rejected'

    New-Item -ItemType Directory -Path $vmRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $vmRoot 'keep.txt') -Value 'existing'
    Assert-Throws { Assert-ReimsFreshDestination $workspace $vmRoot } 'must be empty' 'nonempty destination is never overwritten'
    Remove-Item -LiteralPath $vmRoot -Recurse -Force

    $checkpointRoot = Join-Path $testRoot 'checkpoint'
    New-Item -ItemType Directory -Path $checkpointRoot | Out-Null
    $qemuImg = Join-Path $sourceRoot 'build/qemu/qemu-img.exe'
    Push-Location $checkpointRoot
    try {
        Invoke-ReimsQemuImg $qemuImg @('create','-f','qcow2','base.qcow2','1M') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Fixture base QCOW2 creation failed.' }
        Invoke-ReimsQemuImg $qemuImg @('create','-f','qcow2','-F','qcow2','-b','base.qcow2','current.qcow2') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Fixture overlay QCOW2 creation failed.' }
    } finally { Pop-Location }
    [pscustomobject]@{active_disk=(Join-Path $checkpointRoot 'current.qcow2');base_disk=(Join-Path $checkpointRoot 'base.qcow2')} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $checkpointRoot 'config.json') -Encoding utf8NoBOM
    $checkpointFiles = @('current.qcow2','base.qcow2','OVMF_VARS.fd','config.json','opencore-identity.json')
    $entries = @()
    foreach ($name in $checkpointFiles) {
        $path = Join-Path $checkpointRoot $name
        if ($name -notin @('current.qcow2','base.qcow2','config.json')) { [IO.File]::WriteAllText($path, "fixture:$name") }
        $item = Get-Item -LiteralPath $path
        $entry = [ordered]@{name=$name;bytes=$item.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
        if ($name -eq 'current.qcow2') { $entry.backingFile = 'base.qcow2' }
        elseif ($name -eq 'base.qcow2') { $entry.backingFile = $null }
        $entries += [pscustomobject]$entry
    }
    [pscustomobject]@{schema=1;files=$entries} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $checkpointRoot 'reims-checkpoint.json') -Encoding utf8NoBOM
    $restoreArgs = $common.Clone(); $restoreArgs.Mode = 'Restore'; $restoreArgs.CheckpointRoot = $checkpointRoot; $restoreArgs.VmRoot = Join-Path $workspace 'restore'
    $restore = Get-ReimsReproPlan @restoreArgs
    Assert-Condition ($restore.checkpoint.status -eq 'pass' -and $restore.mode -eq 'Restore' -and $restore.status -eq 'READY_FOR_LATER_APPROVAL') 'complete checkpoint with exact hashes and qcow2 chain is accepted for dry-run'
    Assert-Condition ($restore.checkpoint.backing_file -eq 'base.qcow2' -and @($restore.checkpoint.qcow2_checks).Count -eq 2 -and @($restore.checkpoint.qcow2_checks | Where-Object repair).Count -eq 0) 'QCOW2 overlay and base pass offline checks without repair'
    $checkpointManifestPath = Join-Path $checkpointRoot 'reims-checkpoint.json'
    $wrongBackingManifest = Get-Content $checkpointManifestPath -Raw | ConvertFrom-Json
    ($wrongBackingManifest.files | Where-Object name -EQ 'current.qcow2').backingFile = 'other.qcow2'
    $wrongBackingManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $checkpointManifestPath -Encoding utf8NoBOM
    $wrongBacking = Get-ReimsReproPlan @restoreArgs
    Assert-Condition ($wrongBacking.status -eq 'BLOCKED' -and ($wrongBacking.problems -join ' ') -match 'overlay -> base.qcow2') 'wrong declared backing relationship fails closed'
    [pscustomobject]@{schema=1;files=$entries} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $checkpointManifestPath -Encoding utf8NoBOM
    [IO.File]::AppendAllText((Join-Path $checkpointRoot 'config.json'), 'tampered')
    $tampered = Get-ReimsReproPlan @restoreArgs
    Assert-Condition ($tampered.status -eq 'BLOCKED' -and ($tampered.problems -join ' ') -match 'Checkpoint hash mismatch: config.json') 'checkpoint config/manifest mismatch fails closed'
    $restoreArgs.CheckpointRoot = Join-Path $testRoot 'checkpoint-without-manifest'
    New-Item -ItemType Directory -Path $restoreArgs.CheckpointRoot | Out-Null
    $resume = Get-ReimsReproPlan @restoreArgs
    Assert-Condition ($resume.status -eq 'BLOCKED' -and $resume.checkpoint.status -eq 'missing_manifest') 'resume without checkpoint manifest is blocked'

    $junction = Join-Path $testRoot 'junction'
    try {
        New-Item -ItemType Junction -Path $junction -Target $inputRoot | Out-Null
        Assert-Throws { Assert-ReimsNoReparsePath (Join-Path $junction 'probe.bin') } 'Reparse-point' 'reparse-point path is rejected'
    } catch {
        if ($_.Exception.Message -match 'ASSERT:') { throw }
        $skipped++
    }

    [pscustomobject]@{ assertions=$assertions; skipped=$skipped; passed=$true; qemu_started=$false; destination_created_by_plan=$false } | ConvertTo-Json
} finally {
    $fullTestRoot = [IO.Path]::GetFullPath($testRoot)
    $testPrefix = 'D:\ReimsVM\Issue4-test-'
    if ($fullTestRoot.StartsWith($testPrefix, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $fullTestRoot)) {
        Remove-Item -LiteralPath $fullTestRoot -Recurse -Force
    }
}
