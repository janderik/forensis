"""Tests for disk forensics modules."""

import hashlib
import io
import os
import struct
import zipfile

import pytest
from PIL import Image

from src.disk.carver import FileCarver
from src.disk.filesystem import FilesystemNavigator
from src.disk.imager import DiskImager


def make_jpeg() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (200, 30, 30)).save(buf, format="JPEG")
    return buf.getvalue()


def make_png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (8, 8), (30, 200, 30)).save(buf, format="PNG")
    return buf.getvalue()


def make_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("hello.txt", "content")
    return buf.getvalue()


def make_pdf() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >> endobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n"
        b"0000000058 00000 n \n0000000115 00000 n \n"
        b"trailer << /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF"
    )


def _fat_dir_entry(name: bytes, size: int) -> bytes:
    entry = bytearray(32)
    entry[0:11] = name  # 8.3 name, space padded
    entry[0x0B] = 0x20  # archive attribute
    struct.pack_into("<H", entry, 0x16, (12 << 11) | (30 << 5))  # 12:30:00
    struct.pack_into("<H", entry, 0x18, ((2024 - 1980) << 9) | (3 << 5) | 15)
    struct.pack_into("<I", entry, 0x1C, size)
    return bytes(entry)


def make_fat16_image() -> bytes:
    """FAT16 volume as formatted by real tools (vendor string in the OEM ID)."""
    bps, spc, reserved, nfats, root_entries, fatsz16 = 512, 4, 1, 2, 512, 32
    boot = bytearray(bps)
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into(
        "<HBHBHHBH",
        boot,
        0x0B,
        bps,
        spc,
        reserved,
        nfats,
        root_entries,
        0x8000,
        0xF8,
        fatsz16,
    )
    boot[0x24] = 0x80  # drive number: non-zero bytes where FAT32 keeps its FAT size
    boot[0x26] = 0x29
    boot[0x27:0x2B] = b"\x12\x34\x56\x78"
    boot[0x36:0x3E] = b"FAT16   "
    boot[510:512] = b"\x55\xaa"
    root_offset = (reserved + nfats * fatsz16) * bps
    image = bytearray(root_offset + root_entries * 32 + bps)
    image[0:bps] = boot
    image[root_offset : root_offset + 32] = _fat_dir_entry(b"README  TXT", 1234)
    return bytes(image)


def make_fat32_image() -> bytes:
    """Small FAT32 volume: FAT size below 0x10000 sectors."""
    bps, spc, reserved, nfats, fatsz32, root_cluster = 512, 1, 32, 2, 100, 2
    boot = bytearray(bps)
    boot[3:11] = b"mkfs.fat"
    struct.pack_into("<HBHBHHBH", boot, 0x0B, bps, spc, reserved, nfats, 0, 0, 0xF8, 0)
    struct.pack_into("<I", boot, 0x24, fatsz32)
    struct.pack_into("<I", boot, 0x2C, root_cluster)
    boot[0x52:0x5A] = b"FAT32   "
    boot[510:512] = b"\x55\xaa"
    root_offset = (reserved + nfats * fatsz32 + (root_cluster - 2) * spc) * bps
    image = bytearray(root_offset + 2 * bps)
    image[0:bps] = boot
    image[root_offset : root_offset + 32] = _fat_dir_entry(b"EVIDENCELOG", 42)
    return bytes(image)


class TestDiskImager:
    """Tests for DiskImager."""

    def test_source_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            DiskImager("/nonexistent/source", "dest.img")

    def test_successful_acquisition(self, tmp_path) -> None:
        source = tmp_path / "source.bin"
        source.write_bytes(b"Hello, forensic world!" * 1000)

        dest = tmp_path / "image.dd"
        imager = DiskImager(str(source), str(dest))
        result = imager.acquire()

        assert result["source_size"] == os.path.getsize(str(source))
        assert result["bytes_copied"] == result["source_size"]
        assert result["sha256"] is not None
        assert result["md5"] is not None
        assert result["verified"] is True
        assert dest.exists()
        assert dest.read_bytes() == source.read_bytes()

    def test_source_reporting_zero_size_is_fully_copied(
        self, tmp_path, monkeypatch
    ) -> None:
        """Block devices report size 0 via getsize; the image must not be empty."""
        payload = os.urandom(3 * 1024 * 1024)
        source = tmp_path / "device.bin"
        source.write_bytes(payload)
        dest = tmp_path / "device.dd"

        real_getsize = os.path.getsize
        monkeypatch.setattr(
            os.path,
            "getsize",
            lambda p: 0 if os.fspath(p) == str(source) else real_getsize(p),
        )

        result = DiskImager(str(source), str(dest)).acquire()
        assert result["bytes_copied"] == len(payload)
        assert result["source_size"] == len(payload)
        assert result["sha256"] == hashlib.sha256(payload).hexdigest()
        assert dest.read_bytes() == payload

    def test_empty_source(self, tmp_path) -> None:
        source = tmp_path / "empty.bin"
        source.write_bytes(b"")
        dest = tmp_path / "empty.dd"
        imager = DiskImager(str(source), str(dest))
        result = imager.acquire()
        assert result["bytes_copied"] == 0

    def test_large_block_acquisition(self, tmp_path) -> None:
        source = tmp_path / "large.bin"
        source.write_bytes(b"\xab" * (4 * 1024 * 1024 + 13))  # > 4MB

        dest = tmp_path / "large.dd"
        imager = DiskImager(str(source), str(dest))
        result = imager.acquire()
        assert result["verified"] is True
        assert os.path.getsize(str(dest)) == os.path.getsize(str(source))

    def test_cancellation(self, tmp_path) -> None:
        source = tmp_path / "cancel_source.bin"
        source.write_bytes(b"\xbb" * (8 * 1024 * 1024))
        dest = tmp_path / "cancel.dd"
        imager = DiskImager(str(source), str(dest), verify=False)

        # Cancel immediately
        imager.cancel()
        with pytest.raises(Exception):
            imager.acquire()

    def test_acquisition_log(self, tmp_path) -> None:
        source = tmp_path / "log_source.bin"
        source.write_bytes(b"test data")
        dest = tmp_path / "log_dest.dd"
        log_file = tmp_path / "acquisition.log"

        imager = DiskImager(str(source), str(dest), log_path=str(log_file))
        imager.acquire()
        assert log_file.exists()
        content = log_file.read_text()
        assert "SHA256" in content
        assert "MD5" in content

    def test_create_sparse(self, tmp_path) -> None:
        source = tmp_path / "sparse_source.bin"
        # Create data with null blocks
        data = b"\x00" * 4096 + b"DATA" * 100 + b"\x00" * 4096
        source.write_bytes(data)
        dest = tmp_path / "sparse.dd"

        result = DiskImager.create_sparse(str(source), str(dest))
        assert result["sha256"] is not None


class TestFileCarver:
    """Tests for FileCarver signature-based carving."""

    def test_image_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            FileCarver("/nonexistent/image.raw")

    def test_carve_jpeg(self, tmp_path) -> None:
        image = tmp_path / "image.raw"
        # Embed a JPEG with header and footer
        jpeg_data = make_jpeg()
        image.write_bytes(jpeg_data * 3)  # 3 JPEGs

        output = tmp_path / "carved"
        carver = FileCarver(str(image), str(output))
        results = carver.carve("jpg")
        assert len(results) == 3
        for r in results:
            assert r["file_type"] == "JPEG"
            assert r["extension"] == "jpg"
        assert sum(r["size"] for r in results) == len(jpeg_data) * 3

    def test_carve_png(self, tmp_path) -> None:
        image = tmp_path / "png_test.raw"
        header = b"\x89PNG\r\n\x1a\n"
        # Create a minimal valid PNG structure with IEND
        ihdr = b"IHDR" + b"\x00" * 9 + b"\x00" * 4  # CRC placeholder
        iend = b"IEND" + b"\x00" * 4  # IEND + CRC
        png_data = header + ihdr + b"\x00" * 50 + iend
        image.write_bytes(png_data)

        output = tmp_path / "carved_png"
        carver = FileCarver(str(image), str(output))
        results = carver.carve("png")
        assert len(results) == 1
        assert results[0]["file_type"] == "PNG"

    def test_carve_pdf(self, tmp_path) -> None:
        image = tmp_path / "pdf_test.raw"
        pdf_data = make_pdf()
        image.write_bytes(b"\x00" * 512 + pdf_data + b"\x00" * 512)

        output = tmp_path / "carved_pdf"
        carver = FileCarver(str(image), str(output))
        results = carver.carve("pdf")
        assert len(results) == 1
        assert results[0]["file_type"] == "PDF"

    def test_carve_zip(self, tmp_path) -> None:
        image = tmp_path / "zip_test.raw"
        image.write_bytes(b"\x00" * 512 + make_zip() + b"\x00" * 512)

        output = tmp_path / "carved_zip"
        carver = FileCarver(str(image), str(output))
        results = carver.carve("zip")
        assert len(results) >= 1

    def test_carve_multiple_types(self, tmp_path) -> None:
        image = tmp_path / "multi.raw"
        image.write_bytes(make_jpeg() + b"\x00" * 64 + make_png())

        output = tmp_path / "carved_multi"
        carver = FileCarver(str(image), str(output))
        results = carver.carve_all(types=["jpg", "png"])
        assert len(results) >= 2
        types = [r["file_type"] for r in results]
        assert "JPEG" in types
        assert "PNG" in types

    def test_carve_empty_image_returns_empty(self, tmp_path) -> None:
        image = tmp_path / "empty.raw"
        image.write_bytes(b"")
        output = tmp_path / "carved_empty"
        carver = FileCarver(str(image), str(output))
        results = carver.carve_all()
        assert results == []

    def test_carve_elf(self, tmp_path) -> None:
        image = tmp_path / "elf_test.raw"
        elf = b"\x7fELF" + b"\x00" * 60
        image.write_bytes(elf)

        output = tmp_path / "carved_elf"
        carver = FileCarver(str(image), str(output))
        results = carver.carve("elf")
        assert len(results) == 1

    def test_minimum_size_enforced(self, tmp_path) -> None:
        image = tmp_path / "minsize.raw"
        # JPEG less than min_size (1024)
        image.write_bytes(b"\xff\xd8\xff\xd9")
        output = tmp_path / "carved_min"
        carver = FileCarver(str(image), str(output))
        results = carver.carve("jpg")
        assert len(results) == 0

    def test_output_directory_created(self, tmp_path) -> None:
        image = tmp_path / "dir_test.raw"
        image.write_bytes(b"\xff\xd8\xff" + b"\x00" * 100 + b"\xff\xd9")
        output = tmp_path / "new_dir" / "carved"
        carver = FileCarver(str(image), str(output))
        carver.carve("jpg")
        assert output.exists()


class TestFilesystemNavigator:
    """Tests for FilesystemNavigator."""

    def test_image_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            FilesystemNavigator("/nonexistent/image.raw")

    def test_empty_image_identify(self, tmp_path) -> None:
        image = tmp_path / "empty.img"
        image.write_bytes(b"\x00" * 512)
        nav = FilesystemNavigator(str(image))
        fs = nav.identify_filesystem()
        assert fs is None

    def test_ntfs_boot_sector(self, tmp_path) -> None:
        image = tmp_path / "ntfs.img"
        data = bytearray(512)
        data[3:11] = b"NTFS    "
        data[510:512] = b"\x55\xaa"
        image.write_bytes(data)
        nav = FilesystemNavigator(str(image))
        fs = nav.identify_filesystem()
        assert fs == "NTFS"

    def test_fat32_boot_sector(self, tmp_path) -> None:
        image = tmp_path / "fat32.img"
        data = bytearray(512)
        data[3:11] = b"FAT32   "
        data[510:512] = b"\x55\xaa"
        image.write_bytes(data)
        nav = FilesystemNavigator(str(image))
        fs = nav.identify_filesystem()
        assert fs == "FAT32"

    def test_ext2_superblock(self, tmp_path) -> None:
        image = tmp_path / "ext2.img"
        data = bytearray(2048)
        # ext2 superblock magic at offset 1080 (from start of partition = 1024 + 56)
        struct.pack_into("<H", data, 1080, 0xEF53)
        image.write_bytes(data)
        nav = FilesystemNavigator(str(image))
        fs = nav.identify_filesystem()
        assert fs in ("ext2", "ext3", "ext4")

    def test_empty_list_directory(self, tmp_path) -> None:
        image = tmp_path / "empty_ls.img"
        image.write_bytes(b"\x00" * 1024)
        nav = FilesystemNavigator(str(image))
        entries = nav.list_directory("/")
        assert isinstance(entries, list)

    def test_fallback_listing(self, tmp_path) -> None:
        image = tmp_path / "fallback.img"
        data = b'filename="report.pdf" ' * 10 + b"Content-Type: application/pdf"
        image.write_bytes(data)
        nav = FilesystemNavigator(str(image))
        entries = nav.list_directory("/")
        assert len(entries) >= 1

    def test_mbr_partition_table(self, tmp_path) -> None:
        image = tmp_path / "mbr.img"
        data = bytearray(512)
        data[510:512] = b"\x55\xaa"
        # Partition 1: type 0x07 (NTFS)
        data[446 + 4] = 0x07
        image.write_bytes(data)
        nav = FilesystemNavigator(str(image))
        fs = nav.identify_filesystem()
        assert fs == "NTFS"

    @pytest.mark.parametrize(
        ("builder", "fs_type", "expected_name", "expected_size"),
        [
            (make_fat16_image, "FAT16", "README.TXT", 1234),
            (make_fat32_image, "FAT32", "EVIDENCE.LOG", 42),
        ],
    )
    def test_fat_root_directory_listing(
        self, tmp_path, builder, fs_type, expected_name, expected_size
    ) -> None:
        image = tmp_path / "volume.img"
        image.write_bytes(builder())
        nav = FilesystemNavigator(str(image))
        assert nav.identify_filesystem() == fs_type
        entries = nav.list_directory("/")
        assert [(e.name, e.size) for e in entries] == [(expected_name, expected_size)]
        assert entries[0].modified == "2024-03-15 12:30:00"
