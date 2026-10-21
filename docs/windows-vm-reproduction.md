# Reproduce the Windows-native Tahoe VM

This runbook is a preparation design and dry-run interface. The entry point
currently has **no provisioning mode**: without `-DryRun` it exits before any
write. A fresh installation, checkpoint restore, Recovery download, QEMU boot,
guest disk erase, or host change requires a later explicit approval.

## Inputs and pins

`windows-vm-pins.json` is the source of truth for the reviewed script base,
Reims and QEMU commits, the `metal2vulkan` Cargo pin, executable/ROM hashes,
matched OVMF, OpenCore 1.0.8 and Tahoe Recovery 26.6.2 media hashes. Supply the
Reims checkout at the exact commit as `-PinnedSourceRoot`. `-InputsRoot` is a
read-only directory with the relative layout in that manifest. Missing and
mismatched hashes block the plan; no network access or package installation
is performed.

## Fresh mode

The destination must be empty or absent and a child of the explicitly supplied
workspace. It cannot overlap the installed VM, pinned engine checkout or this
scripts worktree. Existing junctions/reparse points and traversal paths are
rejected. The plan includes a new OpenCore identity, copied OVMF VARS template,
Recovery-only FAT32 image, separate OpenCore and Recovery disks, an independent
empty QCOW2 base plus writable overlay, and deterministic WHPX QEMU argument
template. It does not copy the installed VM or its writable overlay/VARS.

From PowerShell 7.2+ (replace the workspace only with an owner-selected new
directory):

```powershell
$scripts = 'D:\reims-vgpu-issue4'
$source = 'D:\reims-vgpu-windows'
$inputs = $source
$workspace = 'D:\ReimsVM'
$newVm = Join-Path $workspace 'Tahoe-Repro-Fresh-01'
& (Join-Path $scripts 'scripts\windows\reproduce-vm.ps1') `
  -PinnedSourceRoot $source -InputsRoot $inputs `
  -WorkspaceRoot $workspace -VmRoot $newVm -Mode Fresh -DryRun
```

The command only emits a JSON plan. It reports exact expected/actual hashes,
host CPU/GPU/WHPX readiness, outputs, QEMU argv placeholders (without private
identity), rollback notes, stop gates, and whether the conservative physical
space estimate preserves the required 200 GiB. The 128 GiB virtual disk is
sparse; the estimate reserves 40 GiB for installed guest growth plus copied
inputs and working space. A Recovery wrapper copy is budgeted at 16 GiB when
its actual size is not yet known. A blocked plan is a normal fail-closed result.

The Gate A dry run on CEREBRO used the pinned source checkout as `InputsRoot`:
the QEMU executable, qemu-img, Reims DLL and ROM hashes passed. The matched
OVMF pair, OpenCore ZIP and Recovery DMG/chunklist/wrapper were not present in
that input root, so the planner marked them missing instead of reading or
copying anything from the installed VM directory. Its conservative plan
estimated 57.0 GiB of new data; from the observed 243.99 GiB free, that would
leave about 187.0 GiB, below the required reserve. No destination was created.

Execution must later reuse `prepare-opencore.ps1`, `prepare-recovery.ps1`,
`prepare-vm.ps1`, and `start.ps1` with exact pinned local inputs, after the
complete plan is approved. Do not call `bootstrap.ps1` automatically; it
installs packages/toolchains. Do not call the guest setup command unchanged;
it edits timezone, keyboard, sleep and sudoers settings. Online Apple Recovery
installation is interactive and may advance to a newer Tahoe point release;
this flow does not promise byte-identical OS installation.

## Restore mode

Restore takes an explicit **offline private checkpoint**, never the installed
VM directory. The checkpoint must have a `reims-checkpoint.json` manifest with
schema 1 and entries for `current.qcow2`, its `base.qcow2`, `OVMF_VARS.fd`,
`config.json` and `opencore-identity.json`. Each entry records the exact SHA-256
and byte length. Every file is rehashed before it is included in a plan. A
partial checkpoint, unknown file, hash/size mismatch, missing manifest, or any
running QEMU process blocks the plan. The destination remains a separate empty
directory; source checkpoint files are never moved or removed. No blank
pre-install backup can substitute for the installed guest checkpoint.

Example dry run (requires a complete verified checkpoint manifest):

```powershell
& (Join-Path $scripts 'scripts\windows\reproduce-vm.ps1') `
  -PinnedSourceRoot $source -InputsRoot $inputs `
  -WorkspaceRoot $workspace -VmRoot (Join-Path $workspace 'Tahoe-Repro-Restore-01') `
  -Mode Restore -CheckpointRoot 'D:\ApprovedOfflineCheckpoint' -DryRun
```

## Rollback and stop points

Dry runs create no files. A future fresh execution can be rolled back only
before its first guest boot by removing files created in its new destination;
execution should use a creation manifest to distinguish its own outputs. Keep
all source inputs and checkpoints. Once booted, restore requires a separately
approved offline checkpoint with matched guest disk, base, identity and OVMF
VARS. Stop for any source/hash mismatch, reparse path, destination collision,
missing recovery input, active QEMU process in restore mode, or space estimate
below the 200 GiB reserve. Stop before Recovery installation, disk erase,
post-install preference changes or any host/driver change for separate review.
