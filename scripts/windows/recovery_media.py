"""Build and inspect the pinned, file-backed OpenCore Recovery FAT32 disk."""

from __future__ import annotations

import hashlib
import json
import math
import os
import plistlib
import struct
import uuid
import zlib
from pathlib import Path


PINNED_DMG_SHA256 = "EDDDD0D5869CAAA12E29E6996A04F11590280580976A119DBD42C24FA62FE18E"
PINNED_CHUNKLIST_SHA256 = "06F7C498F856341F467BA1FAEDF2717FB2C172AE0AFF4658A1467CBF46B711F9"
PINNED_OPENCORE_BOOT_SHA256 = "D0163DFBE5D2EA46AECECD7D7349ACFA5B75DFED2993E8489816F3DDA71914C8"
EXPECTED_PRODUCT_VERSION = "26.6.2"
EXPECTED_PRODUCT_BUILD = "25G83"
SECTOR = 512
CLUSTER_SECTORS = 16
RESERVED_SECTORS = 32
FAT_COUNT = 2
PARTITION_START = 2048
DISK_SECTORS = 2_621_440  # 1.25 GiB, enough headroom for this Recovery payload.
ESP_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def _pe_machine(path: Path) -> int:
    with path.open("rb") as source:
        header = source.read(4096)
    return _pe_machine_bytes(header, path.name)


def _pe_machine_bytes(header: bytes, name: str) -> int:
    if len(header) < 64 or header[:2] != b"MZ":
        raise ValueError(f"{name} is not a PE image.")
    offset = struct.unpack_from("<I", header, 0x3C)[0]
    if offset + 6 > len(header) or header[offset : offset + 4] != b"PE\0\0":
        raise ValueError(f"{name} has a truncated or invalid PE header.")
    return struct.unpack_from("<H", header, offset + 4)[0]


def validate_payload(version_plist: Path, standalone_booter: Path) -> dict:
    version = plistlib.loads(Path(version_plist).read_bytes())
    product = version.get("ProductVersion")
    build = version.get("ProductBuildVersion")
    if product != EXPECTED_PRODUCT_VERSION or build != EXPECTED_PRODUCT_BUILD:
        raise ValueError(
            f"Recovery must be Tahoe {EXPECTED_PRODUCT_VERSION} / "
            f"{EXPECTED_PRODUCT_BUILD}; found {product} / {build}."
        )
    booter = Path(standalone_booter)
    if not booter.is_file() or booter.stat().st_size == 0:
        raise ValueError("Standalone usr/standalone/i386/boot.efi is missing or empty.")
    if _pe_machine(booter) != 0x8664:
        raise ValueError("Standalone Recovery boot.efi is not x86_64.")
    return {
        "product_version": product,
        "product_build": build,
        "boot_architecture": "x86_64",
        "boot_bytes": booter.stat().st_size,
        "boot_sha256": _sha256(booter),
    }


def _short_name(name: str, used: set[bytes]) -> bytes:
    stem, dot, extension = name.rpartition(".")
    if not dot:
        stem, extension = name, ""
    clean_stem = "".join(c for c in stem.upper() if c.isascii() and (c.isalnum() or c in "_$~!#%&-{}()@'`"))
    clean_ext = "".join(c for c in extension.upper() if c.isascii() and c.isalnum())
    direct = clean_stem[:8].ljust(8) + clean_ext[:3].ljust(3)
    direct = direct.encode("ascii")
    if len(clean_stem) <= 8 and len(clean_ext) <= 3 and direct not in used:
        used.add(direct)
        return direct
    base = clean_stem or "FILE"
    for index in range(1, 10_000):
        alias = (base[: 7 - len(str(index))] + "~" + str(index)).ljust(8) + clean_ext[:3].ljust(3)
        raw = alias.encode("ascii")
        if raw not in used:
            used.add(raw)
            return raw
    raise ValueError("Unable to allocate a unique FAT short filename.")


def _lfn_entries(name: str, checksum: int) -> list[bytes]:
    encoded = name.encode("utf-16le")
    units = [encoded[i : i + 2] for i in range(0, len(encoded), 2)] + [b"\0\0"]
    while len(units) % 13:
        units.append(b"\xff\xff")
    chunks = [units[i : i + 13] for i in range(0, len(units), 13)]
    out = []
    for seq in range(len(chunks), 0, -1):
        item = bytearray(32)
        item[0] = seq | (0x40 if seq == len(chunks) else 0)
        item[11] = 0x0F
        item[12] = 0
        item[13] = checksum
        item[26:28] = b"\0\0"
        chars = b"".join(chunks[seq - 1])
        item[1:11] = chars[0:10]
        item[14:26] = chars[10:22]
        item[28:32] = chars[22:26]
        out.append(bytes(item))
    return out


def _directory_entry(name: str, cluster: int, size: int, is_dir: bool, used: set[bytes]) -> bytes:
    if name in (".", ".."):
        item = bytearray(32)
        item[:11] = ("." if name == "." else "..").ljust(11).encode("ascii")
        item[11] = 0x10
        struct.pack_into("<H", item, 20, cluster >> 16)
        struct.pack_into("<H", item, 26, cluster & 0xFFFF)
        return bytes(item)
    short = _short_name(name, used)
    item = bytearray(32)
    item[:11] = short
    item[11] = 0x10 if is_dir else 0x20
    struct.pack_into("<H", item, 20, cluster >> 16)
    struct.pack_into("<H", item, 26, cluster & 0xFFFF)
    struct.pack_into("<I", item, 28, size)
    checksum = 0
    for byte in short:
        checksum = (((checksum & 1) << 7) | (checksum >> 1)) + byte
        checksum &= 0xFF
    return b"".join(_lfn_entries(name, checksum)) + bytes(item)


def _gpt_header(current: int, backup: int, first_usable: int, last_usable: int, table_lba: int, table_crc: int) -> bytes:
    header = bytearray(SECTOR)
    struct.pack_into("<8sIIIIQQQQ16sQIII", header, 0,
        b"EFI PART", 0x00010000, 92, 0, 0, current, backup,
        first_usable, last_usable, uuid.UUID("697e1e65-488b-4ef2-90f7-1ae2e045a083").bytes_le,
        table_lba, 128, 128, table_crc)
    struct.pack_into("<I", header, 16, zlib.crc32(header[:92]) & 0xFFFFFFFF)
    return bytes(header)


def _fat_geometry(volume_sectors: int) -> tuple[int, int]:
    fat_sectors = 1
    while True:
        clusters = (volume_sectors - RESERVED_SECTORS - FAT_COUNT * fat_sectors) // CLUSTER_SECTORS
        next_fat = math.ceil((clusters + 2) * 4 / SECTOR)
        if next_fat == fat_sectors:
            break
        fat_sectors = next_fat
    if clusters < 65_525:
        raise ValueError("Recovery volume is too small to be FAT32.")
    return fat_sectors, clusters


def _boot_sector(volume_sectors: int, fat_sectors: int) -> bytes:
    sector = bytearray(SECTOR)
    sector[:3] = b"\xeb\x58\x90"
    sector[3:11] = b"MSWIN4.1"
    struct.pack_into("<HBHBHHBHHHII", sector, 11,
        SECTOR, CLUSTER_SECTORS, RESERVED_SECTORS, FAT_COUNT, 0, 0, 0xF8,
        0, 63, 255, PARTITION_START, volume_sectors)
    struct.pack_into("<IHHIHH", sector, 36, fat_sectors, 0, 0, 2, 1, 6)
    sector[64] = 0x80
    sector[66] = 0x29
    struct.pack_into("<I", sector, 67, 0xA83E1701)
    sector[71:82] = b"RECOVERY   "
    sector[82:90] = b"FAT32   "
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


def _fsinfo() -> bytes:
    info = bytearray(SECTOR)
    struct.pack_into("<I", info, 0, 0x41615252)
    struct.pack_into("<I", info, 484, 0x61417272)
    struct.pack_into("<I", info, 488, 0xFFFFFFFF)
    struct.pack_into("<I", info, 492, 6)
    struct.pack_into("<I", info, 508, 0xAA550000)
    return bytes(info)


def create_wrapper(output: Path, dmg: Path, chunklist: Path, bootx64: Path | None) -> dict:
    recovery_only = bootx64 is None
    output, dmg, chunklist = map(Path, (output, dmg, chunklist))
    if bootx64 is not None:
        bootx64 = Path(bootx64)
    inputs = [(dmg, "BaseSystem.dmg"), (chunklist, "BaseSystem.chunklist")]
    if bootx64 is not None:
        inputs.append((bootx64, "EFI/BOOT/BOOTx64.efi"))
    for path, label in inputs:
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"{label} is missing or empty.")
    if _sha256(dmg) != PINNED_DMG_SHA256:
        raise ValueError("BaseSystem.dmg SHA-256 does not match the reviewed Apple Recovery pin.")
    if _sha256(chunklist) != PINNED_CHUNKLIST_SHA256:
        raise ValueError("BaseSystem.chunklist SHA-256 does not match the reviewed Apple Recovery pin.")
    if bootx64 is not None:
        if _sha256(bootx64) != PINNED_OPENCORE_BOOT_SHA256:
            raise ValueError("EFI/BOOT/BOOTx64.efi SHA-256 does not match OpenCore 1.0.8.")
        if _pe_machine(bootx64) != 0x8664:
            raise ValueError("EFI/BOOT/BOOTx64.efi is not x86_64.")
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite Recovery wrapper: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_name(output.name + ".building")
    if temp.exists():
        raise FileExistsError(f"Refusing to overwrite build temporary: {temp}")

    volume_sectors = DISK_SECTORS - PARTITION_START - 34
    fat_sectors, cluster_count = _fat_geometry(volume_sectors)
    data_start = PARTITION_START + RESERVED_SECTORS + FAT_COUNT * fat_sectors
    cluster_bytes = CLUSTER_SECTORS * SECTOR
    fat = [0] * (cluster_count + 2)
    fat[0:3] = [0x0FFFFFF8, 0xFFFFFFFF, 0x0FFFFFFF]
    if recovery_only:
        directory_clusters = {"": 2, "com.apple.recovery.boot": 3}
    else:
        directory_clusters = {
            "": 2,
            "EFI": 3,
            "EFI/BOOT": 4,
            "com.apple.recovery.boot": 5,
        }
    for cluster in directory_clusters.values():
        fat[cluster] = 0x0FFFFFFF
    files = {}
    if bootx64 is not None:
        files["EFI/BOOT/BOOTx64.efi"] = bootx64
    files["com.apple.recovery.boot/BaseSystem.dmg"] = dmg
    files["com.apple.recovery.boot/BaseSystem.chunklist"] = chunklist
    allocated: dict[str, list[int]] = {}
    next_cluster = 6
    for name, path in files.items():
        count = max(1, math.ceil(path.stat().st_size / cluster_bytes))
        clusters = list(range(next_cluster, next_cluster + count))
        next_cluster += count
        allocated[name] = clusters
        for left, right in zip(clusters, clusters[1:]):
            fat[left] = right
        fat[clusters[-1]] = 0x0FFFFFFF
    if next_cluster >= cluster_count + 2:
        raise ValueError("Recovery files do not fit in the FAT32 partition.")

    def make_dir(path: str, children: list[tuple[str, int, int, bool]]) -> bytes:
        used: set[bytes] = set()
        data = bytearray()
        if path:
            cluster = directory_clusters[path]
            parent_path = path.rpartition("/")[0]
            parent = directory_clusters[parent_path]
            data.extend(_directory_entry(".", cluster, 0, True, used))
            data.extend(_directory_entry("..", parent, 0, True, used))
        for name, cluster, size, is_dir in children:
            data.extend(_directory_entry(name, cluster, size, is_dir, used))
        data.extend(b"\0" * 32)
        return bytes(data).ljust(cluster_bytes, b"\0")

    children: dict[str, list[tuple[str, int, int, bool]]] = {path: [] for path in directory_clusters}
    if not recovery_only:
        children[""].append(("EFI", directory_clusters["EFI"], 0, True))
        children[""].append(("com.apple.recovery.boot", directory_clusters["com.apple.recovery.boot"], 0, True))
        children["EFI"].append(("BOOT", directory_clusters["EFI/BOOT"], 0, True))
    else:
        children[""].append(("com.apple.recovery.boot", directory_clusters["com.apple.recovery.boot"], 0, True))
    for path, source in files.items():
        parent, _, name = path.rpartition("/")
        children[parent].append((name, allocated[path][0], source.stat().st_size, False))
    directories = {path: make_dir(path, entries) for path, entries in children.items()}

    try:
        with temp.open("xb") as disk:
            disk.truncate(DISK_SECTORS * SECTOR)
            protective_mbr = bytearray(SECTOR)
            protective_mbr[446 + 4] = 0xEE
            struct.pack_into("<II", protective_mbr, 446 + 8, 1, min(DISK_SECTORS - 1, 0xFFFFFFFF))
            protective_mbr[510:512] = b"\x55\xaa"
            disk.seek(0); disk.write(protective_mbr)
            entry = bytearray(128)
            entry[:16] = ESP_TYPE.bytes_le
            entry[16:32] = uuid.uuid5(uuid.NAMESPACE_OID, "reims-tahoe-recovery-1g1").bytes_le
            last_lba = PARTITION_START + volume_sectors - 1
            struct.pack_into("<QQQ", entry, 32, PARTITION_START, last_lba, 0)
            entry[56:128] = "OpenCore Recovery".encode("utf-16le").ljust(72, b"\0")
            table = bytes(entry) + bytes(128 * 127)
            table_crc = zlib.crc32(table) & 0xFFFFFFFF
            disk.seek(2 * SECTOR); disk.write(table)
            disk.seek(SECTOR); disk.write(_gpt_header(1, DISK_SECTORS - 1, 34, DISK_SECTORS - 34, 2, table_crc))
            backup_table_lba = DISK_SECTORS - 33
            disk.seek(backup_table_lba * SECTOR); disk.write(table)
            disk.seek((DISK_SECTORS - 1) * SECTOR)
            disk.write(_gpt_header(DISK_SECTORS - 1, 1, 34, DISK_SECTORS - 34, backup_table_lba, table_crc))

            disk.seek(PARTITION_START * SECTOR)
            boot_sector = _boot_sector(volume_sectors, fat_sectors)
            disk.write(boot_sector)
            disk.write(_fsinfo())
            disk.seek((PARTITION_START + 6) * SECTOR); disk.write(boot_sector)
            disk.seek((PARTITION_START + 7) * SECTOR); disk.write(_fsinfo())
            fat_bytes = b"".join(struct.pack("<I", value) for value in fat)
            fat_bytes = fat_bytes.ljust(fat_sectors * SECTOR, b"\0")
            for copy in range(FAT_COUNT):
                disk.seek((PARTITION_START + RESERVED_SECTORS + copy * fat_sectors) * SECTOR)
                disk.write(fat_bytes)

            for path, data in directories.items():
                cluster = directory_clusters[path]
                offset = (data_start + (cluster - 2) * CLUSTER_SECTORS) * SECTOR
                disk.seek(offset); disk.write(data)
            for path, source_path in files.items():
                clusters = allocated[path]
                with source_path.open("rb") as source:
                    for cluster in clusters:
                        block = source.read(cluster_bytes)
                        if not block:
                            break
                        offset = (data_start + (cluster - 2) * CLUSTER_SECTORS) * SECTOR
                        disk.seek(offset); disk.write(block)
        os.replace(temp, output)
    finally:
        if temp.exists():
            temp.unlink()
    return inspect_wrapper(output)


def _read_exact(disk, offset: int, size: int) -> bytes:
    disk.seek(offset)
    data = disk.read(size)
    if len(data) != size:
        raise ValueError("Recovery wrapper is truncated.")
    return data


def _verify_gpt(disk, disk_sectors: int) -> tuple[int, int]:
    mbr = _read_exact(disk, 0, SECTOR)
    if mbr[510:512] != b"\x55\xaa" or mbr[450] != 0xEE:
        raise ValueError("Recovery wrapper has no protective GPT MBR.")
    header = bytearray(_read_exact(disk, SECTOR, SECTOR))
    if header[:8] != b"EFI PART":
        raise ValueError("Recovery wrapper is not a GPT disk.")
    header_size = struct.unpack_from("<I", header, 12)[0]
    expected_crc = struct.unpack_from("<I", header, 16)[0]
    struct.pack_into("<I", header, 16, 0)
    if header_size != 92 or zlib.crc32(header[:header_size]) & 0xFFFFFFFF != expected_crc:
        raise ValueError("Recovery wrapper GPT header checksum is invalid.")
    current, backup = struct.unpack_from("<QQ", header, 24)
    table_lba, count, entry_size, table_crc = struct.unpack_from("<QIII", header, 72)
    if current != 1 or backup != disk_sectors - 1 or count != 128 or entry_size != 128:
        raise ValueError("Recovery wrapper GPT geometry is invalid.")
    table = _read_exact(disk, table_lba * SECTOR, count * entry_size)
    if zlib.crc32(table) & 0xFFFFFFFF != table_crc:
        raise ValueError("Recovery wrapper GPT partition table checksum is invalid.")
    for offset in range(0, len(table), entry_size):
        entry = table[offset : offset + entry_size]
        if entry[:16] == ESP_TYPE.bytes_le:
            first, last = struct.unpack_from("<QQ", entry, 32)
            if first < 34 or last >= disk_sectors - 33 or last < first:
                raise ValueError("Recovery wrapper ESP bounds are invalid.")
            return first, last - first + 1
    raise ValueError("Recovery wrapper GPT has no EFI System partition.")


def _fat_directory(disk, volume_start: int, data_start: int, cluster_bytes: int, fat_offset: int, fat_sectors: int, cluster_count: int, start_cluster: int, fat_cache: dict[int, int]) -> list[tuple[str, int, int, bool]]:
    cluster = start_cluster
    content = bytearray()
    seen: set[int] = set()
    while cluster < 0x0FFFFFF8:
        if cluster < 2 or cluster >= cluster_count + 2 or cluster in seen:
            raise ValueError("Recovery wrapper FAT cluster chain is invalid.")
        seen.add(cluster)
        content.extend(_read_exact(disk, data_start * SECTOR + (cluster - 2) * cluster_bytes, cluster_bytes))
        if cluster not in fat_cache:
            fat_cache[cluster] = struct.unpack("<I", _read_exact(disk, fat_offset + cluster * 4, 4))[0] & 0x0FFFFFFF
        cluster = fat_cache[cluster]
    result: list[tuple[str, int, int, bool]] = []
    long_parts: dict[int, bytes] = {}
    for offset in range(0, len(content), 32):
        entry = content[offset : offset + 32]
        if entry[0] == 0:
            break
        if entry[0] == 0xE5:
            long_parts.clear(); continue
        if entry[11] == 0x0F:
            seq = entry[0] & 0x1F
            chars = entry[1:11] + entry[14:26] + entry[28:32]
            long_parts[seq] = chars
            continue
        if entry[11] & 0x08:
            long_parts.clear(); continue
        name = ""
        if long_parts:
            raw = b"".join(long_parts[key] for key in sorted(long_parts))
            name = raw.decode("utf-16le", errors="strict").split("\0", 1)[0].replace("\uffff", "")
        else:
            short = entry[:11].decode("ascii", errors="strict").rstrip()
            name = short.replace(" ", "")
            if name[0:8] != "" and "." not in name and short[8:11].strip():
                name = name[:8].rstrip() + "." + short[8:11].strip()
        cluster_id = (struct.unpack_from("<H", entry, 20)[0] << 16) | struct.unpack_from("<H", entry, 26)[0]
        result.append((name, cluster_id, struct.unpack_from("<I", entry, 28)[0], bool(entry[11] & 0x10)))
        long_parts.clear()
    return result


def _file_hash(disk, data_start: int, cluster_bytes: int, start_cluster: int, size: int, cluster_count: int, fat_offset: int, fat_cache: dict[int, int]) -> str:
    digest = hashlib.sha256()
    left = size
    cluster = start_cluster
    seen: set[int] = set()
    while left:
        if cluster < 2 or cluster >= cluster_count + 2 or cluster in seen:
            raise ValueError("Recovery wrapper file cluster chain is invalid.")
        seen.add(cluster)
        amount = min(left, cluster_bytes)
        digest.update(_read_exact(disk, data_start * SECTOR + (cluster - 2) * cluster_bytes, amount))
        left -= amount
        if not left:
            break
        if cluster not in fat_cache:
            fat_cache[cluster] = struct.unpack("<I", _read_exact(disk, fat_offset + cluster * 4, 4))[0] & 0x0FFFFFFF
        cluster = fat_cache[cluster]
    return digest.hexdigest().upper()


def _file_prefix(disk, data_start: int, cluster_bytes: int, start_cluster: int, size: int, wanted: int, cluster_count: int, fat_offset: int, fat_cache: dict[int, int]) -> bytes:
    output = bytearray()
    left = min(size, wanted)
    cluster = start_cluster
    seen: set[int] = set()
    while left:
        if cluster < 2 or cluster >= cluster_count + 2 or cluster in seen:
            raise ValueError("Recovery wrapper EFI file cluster chain is invalid.")
        seen.add(cluster)
        amount = min(left, cluster_bytes)
        output.extend(_read_exact(disk, data_start * SECTOR + (cluster - 2) * cluster_bytes, amount))
        left -= amount
        if left:
            if cluster not in fat_cache:
                fat_cache[cluster] = struct.unpack("<I", _read_exact(disk, fat_offset + cluster * 4, 4))[0] & 0x0FFFFFFF
            cluster = fat_cache[cluster]
    return bytes(output)


def inspect_wrapper(image: Path) -> dict:
    image = Path(image)
    if not image.is_file() or image.stat().st_size % SECTOR:
        raise ValueError("Recovery wrapper is missing or has invalid raw-disk length.")
    disk_sectors = image.stat().st_size // SECTOR
    with image.open("rb") as disk:
        volume_start, volume_sectors = _verify_gpt(disk, disk_sectors)
        boot = _read_exact(disk, volume_start * SECTOR, SECTOR)
        if boot[510:512] != b"\x55\xaa" or boot[82:90] != b"FAT32   ":
            raise ValueError("Recovery wrapper EFI System partition is not FAT32.")
        bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
        sectors_per_cluster = boot[13]
        reserved = struct.unpack_from("<H", boot, 14)[0]
        fat_count = boot[16]
        fat_sectors = struct.unpack_from("<I", boot, 36)[0]
        root_cluster = struct.unpack_from("<I", boot, 44)[0]
        if bytes_per_sector != SECTOR or not sectors_per_cluster or reserved < 32 or fat_count != 2 or not fat_sectors:
            raise ValueError("Recovery wrapper FAT32 geometry is invalid.")
        if struct.unpack_from("<H", boot, 48)[0] != 1 or struct.unpack_from("<H", boot, 50)[0] != 6:
            raise ValueError("Recovery wrapper FAT32 backup metadata is invalid.")
        if struct.unpack_from("<I", _read_exact(disk, (volume_start + 1) * SECTOR, SECTOR), 0)[0] != 0x41615252:
            raise ValueError("Recovery wrapper FAT32 FSInfo is invalid.")
        cluster_bytes = bytes_per_sector * sectors_per_cluster
        data_sectors = volume_sectors - reserved - fat_count * fat_sectors
        cluster_count = data_sectors // sectors_per_cluster
        if cluster_count < 65_525:
            raise ValueError("Recovery wrapper partition is not FAT32 by cluster count.")
        fat_offset = (volume_start + reserved) * SECTOR
        data_start = volume_start + reserved + fat_count * fat_sectors
        fat_cache: dict[int, int] = {}
        files: dict[str, dict] = {}
        file_clusters: dict[str, tuple[int, int]] = {}
        directories: set[str] = set()

        def walk(directory: str, cluster: int, depth: int = 0):
            if depth > 4:
                raise ValueError("Recovery wrapper directory nesting is invalid.")
            for name, child, size, is_dir in _fat_directory(
                disk, volume_start, data_start, cluster_bytes, fat_offset, fat_sectors,
                cluster_count, cluster, fat_cache
            ):
                if name in (".", ".."):
                    continue
                path = f"{directory}/{name}" if directory else name
                if is_dir:
                    directories.add(path.casefold())
                    walk(path, child, depth + 1)
                else:
                    key = path.casefold()
                    files[key] = {
                        "bytes": size,
                        "sha256": _file_hash(disk, data_start, cluster_bytes, child, size,
                                             cluster_count, fat_offset, fat_cache),
                    }
                    file_clusters[key] = (child, size)

        walk("", root_cluster)
    recovery_files = {
        "com.apple.recovery.boot/basesystem.dmg",
        "com.apple.recovery.boot/basesystem.chunklist",
    }
    fallback = "efi/boot/bootx64.efi"
    recovery_only = set(files) == recovery_files
    required = recovery_files if recovery_only else recovery_files | {fallback}
    missing = required - files.keys()
    if missing:
        raise ValueError("Recovery wrapper is missing required contents: " + ", ".join(sorted(missing)))
    if recovery_only and "efi" in directories:
        raise ValueError("Recovery-only wrapper must not contain an EFI directory or competing fallback.")
    if recovery_only and set(files) != recovery_files:
        raise ValueError("Recovery-only wrapper must contain exactly the two pinned Apple payload files.")
    if files["com.apple.recovery.boot/basesystem.dmg"]["sha256"] != PINNED_DMG_SHA256:
        raise ValueError("Recovery wrapper BaseSystem.dmg SHA-256 differs from the reviewed Apple pin.")
    if files["com.apple.recovery.boot/basesystem.chunklist"]["sha256"] != PINNED_CHUNKLIST_SHA256:
        raise ValueError("Recovery wrapper BaseSystem.chunklist SHA-256 differs from the reviewed Apple pin.")
    if not recovery_only and files[fallback]["sha256"] != PINNED_OPENCORE_BOOT_SHA256:
        raise ValueError("Recovery wrapper EFI/BOOT/BOOTx64.efi differs from OpenCore 1.0.8.")
    if recovery_only:
        return {
            "schema": 1,
            "path": str(image.resolve()),
            "bytes": image.stat().st_size,
            "container": "GPT/FAT32",
            "media_kind": "disk",
            "wrapper_mode": "recovery-only",
            "directories": sorted(directories),
            "files": files,
        }
    boot_cluster, boot_bytes = file_clusters["efi/boot/bootx64.efi"]
    with image.open("rb") as disk:
        # Reuse the validated geometry while reading only the PE header.
        start, count = _verify_gpt(disk, disk_sectors)
        bpb = _read_exact(disk, start * SECTOR, SECTOR)
        reserved = struct.unpack_from("<H", bpb, 14)[0]
        fat_count = bpb[16]
        fat_sectors = struct.unpack_from("<I", bpb, 36)[0]
        sectors_per_cluster = bpb[13]
        data_start = start + reserved + fat_count * fat_sectors
        cluster_count = (count - reserved - fat_count * fat_sectors) // sectors_per_cluster
        cluster_bytes = sectors_per_cluster * SECTOR
        fat_cache = {}
        prefix = _file_prefix(disk, data_start, cluster_bytes, boot_cluster, boot_bytes, 4096,
                              cluster_count, (start + reserved) * SECTOR, fat_cache)
    if _pe_machine_bytes(prefix, "EFI/BOOT/BOOTx64.efi") != 0x8664:
        raise ValueError("EFI/BOOT/BOOTx64.efi is not x86_64.")
    return {
        "schema": 1,
        "path": str(image.resolve()),
        "bytes": image.stat().st_size,
        "container": "GPT/FAT32",
        "media_kind": "disk",
        "wrapper_mode": "full",
        "boot_architecture": "x86_64",
        "files": files,
    }


def verify_apple_chunklist(dmg: Path, chunklist: Path, macrecovery: Path) -> dict:
    """Use the pinned OpenCore verifier for both signature and every image chunk."""
    import importlib.util

    dmg, chunklist, macrecovery = map(Path, (dmg, chunklist, macrecovery))
    if _sha256(dmg) != PINNED_DMG_SHA256 or _sha256(chunklist) != PINNED_CHUNKLIST_SHA256:
        raise ValueError("Apple Recovery source hashes differ from the reviewed pins.")
    spec = importlib.util.spec_from_file_location("reims_macrecovery", macrecovery)
    if spec is None or spec.loader is None:
        raise ValueError("Pinned OpenCore macrecovery.py cannot be loaded.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    chunks = list(module.verify_chunklist(str(chunklist)))
    module.verify_image(str(dmg), str(chunklist))
    return {"chunk_count": len(chunks), "dmg_sha256": PINNED_DMG_SHA256,
            "chunklist_sha256": PINNED_CHUNKLIST_SHA256}


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--dmg", type=Path, required=True)
    build.add_argument("--chunklist", type=Path, required=True)
    build.add_argument("--bootx64", type=Path, required=True)
    recovery = sub.add_parser("build-recovery-only")
    recovery.add_argument("--output", type=Path, required=True)
    recovery.add_argument("--dmg", type=Path, required=True)
    recovery.add_argument("--chunklist", type=Path, required=True)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("--image", type=Path, required=True)
    payload = sub.add_parser("validate-payload")
    payload.add_argument("--version-plist", type=Path, required=True)
    payload.add_argument("--booter", type=Path, required=True)
    verify = sub.add_parser("verify-chunklist")
    verify.add_argument("--dmg", type=Path, required=True)
    verify.add_argument("--chunklist", type=Path, required=True)
    verify.add_argument("--macrecovery", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        result = create_wrapper(args.output, args.dmg, args.chunklist, args.bootx64)
    elif args.command == "build-recovery-only":
        result = create_wrapper(args.output, args.dmg, args.chunklist, None)
    elif args.command == "inspect":
        result = inspect_wrapper(args.image)
    elif args.command == "validate-payload":
        result = validate_payload(args.version_plist, args.booter)
    else:
        result = verify_apple_chunklist(args.dmg, args.chunklist, args.macrecovery)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
