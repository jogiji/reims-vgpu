import hashlib
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import recovery_media


def make_pe(machine=0x8664, size=256):
    data = bytearray(size)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (128).to_bytes(4, "little")
    data[128:132] = b"PE\0\0"
    data[132:134] = machine.to_bytes(2, "little")
    return bytes(data)


class RecoveryMediaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dmg = self.root / "BaseSystem.dmg"
        self.chunklist = self.root / "BaseSystem.chunklist"
        self.boot = self.root / "BOOTx64.efi"
        self.image = self.root / "Recovery-wrapper.raw"
        self.dmg.write_bytes(b"reviewed Tahoe recovery fixture\0" * 8192)
        self.chunklist.write_bytes(b"signed chunklist fixture\0" * 32)
        self.boot.write_bytes(make_pe())
        self.pin = {
            "dmg": hashlib.sha256(self.dmg.read_bytes()).hexdigest().upper(),
            "chunklist": hashlib.sha256(self.chunklist.read_bytes()).hexdigest().upper(),
            "boot": hashlib.sha256(self.boot.read_bytes()).hexdigest().upper(),
        }

    def tearDown(self):
        self.temp.cleanup()

    def build(self, boot=None):
        with patch.object(recovery_media, "PINNED_DMG_SHA256", self.pin["dmg"]), patch.object(
            recovery_media, "PINNED_CHUNKLIST_SHA256", self.pin["chunklist"]
        ), patch.object(recovery_media, "PINNED_OPENCORE_BOOT_SHA256", self.pin["boot"]):
            recovery_media.create_wrapper(
                self.image, self.dmg, self.chunklist, boot or self.boot
            )
            return recovery_media.inspect_wrapper(self.image)

    def test_valid_wrapper_preserves_pinned_payload_and_recovery_layout(self):
        result = self.build()

        self.assertEqual("disk", result["media_kind"])
        self.assertEqual("GPT/FAT32", result["container"])
        self.assertEqual("x86_64", result["boot_architecture"])
        self.assertEqual(self.pin["dmg"], result["files"]["com.apple.recovery.boot/basesystem.dmg"]["sha256"])
        self.assertEqual(self.pin["chunklist"], result["files"]["com.apple.recovery.boot/basesystem.chunklist"]["sha256"])
        self.assertIn("efi/boot/bootx64.efi", result["files"])

    def test_changed_dmg_or_missing_chunklist_is_refused(self):
        self.dmg.write_bytes(b"altered Tahoe recovery")
        with self.assertRaisesRegex(ValueError, "BaseSystem.dmg SHA-256"):
            self.build()

        self.dmg.write_bytes(b"reviewed Tahoe recovery fixture\0" * 8192)
        self.chunklist.write_bytes(b"damaged signed chunklist")
        with self.assertRaisesRegex(ValueError, "chunklist SHA-256"):
            self.build()

        self.chunklist.write_bytes(b"signed chunklist fixture\0" * 32)
        self.chunklist.unlink()
        with self.assertRaisesRegex(ValueError, "chunklist.*missing"):
            self.build()

    def test_wrong_efi_architecture_and_unknown_container_are_refused(self):
        self.boot.write_bytes(make_pe(machine=0xAA64))
        self.pin["boot"] = hashlib.sha256(self.boot.read_bytes()).hexdigest().upper()
        with self.assertRaisesRegex(ValueError, "x86_64"):
            self.build()

        self.boot.write_bytes(make_pe())
        self.pin["boot"] = hashlib.sha256(self.boot.read_bytes()).hexdigest().upper()
        self.build()
        with self.image.open("r+b") as image:
            image.seek(512)
            image.write(b"BAD GPT!")
        with self.assertRaisesRegex(ValueError, "GPT"):
            recovery_media.inspect_wrapper(self.image)

    def test_changed_x64_fallback_hash_is_refused(self):
        self.boot.write_bytes(make_pe() + b"changed")
        with self.assertRaisesRegex(ValueError, "OpenCore 1.0.8"):
            self.build()

    def test_misplaced_efi_tree_is_refused(self):
        self.build()
        with self.image.open("r+b") as image:
            image.seek(2048 * 512)
            boot = image.read(512)
            reserved = int.from_bytes(boot[14:16], "little")
            fat_count = boot[16]
            fat_sectors = int.from_bytes(boot[36:40], "little")
            sectors_per_cluster = boot[13]
            data_start = 2048 + reserved + fat_count * fat_sectors
            root_offset = data_start * 512
            image.seek(root_offset + 1)
            image.write(b"X")
        with self.assertRaisesRegex(ValueError, "missing required contents"):
            recovery_media.inspect_wrapper(self.image)

    def test_nested_payload_requires_tahoe_2662_and_nonempty_x64_standalone_booter(self):
        version = self.root / "SystemVersion.plist"
        booter = self.root / "standalone-boot.efi"
        version.write_bytes(
            plistlib.dumps({"ProductVersion": "26.6.2", "ProductBuildVersion": "25G83"})
        )
        booter.write_bytes(make_pe())
        result = recovery_media.validate_payload(version, booter)
        self.assertEqual("26.6.2", result["product_version"])
        self.assertEqual("25G83", result["product_build"])

        for product, build in (("27.0", "26A1"), ("26.6.2", "wrong")):
            version.write_bytes(
                plistlib.dumps({"ProductVersion": product, "ProductBuildVersion": build})
            )
            with self.assertRaisesRegex(ValueError, "26.6.2 / 25G83"):
                recovery_media.validate_payload(version, booter)

        version.write_bytes(
            plistlib.dumps({"ProductVersion": "26.6.2", "ProductBuildVersion": "25G83"})
        )
        for data in (b"", b"MZ", make_pe(machine=0xAA64)):
            booter.write_bytes(data)
            with self.assertRaises(ValueError):
                recovery_media.validate_payload(version, booter)


if __name__ == "__main__":
    unittest.main(verbosity=2)
