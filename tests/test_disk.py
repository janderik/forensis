"""Tests for disk forensics modules."""

import os
import struct

import pytest

from src.disk.carver import FileCarver, FileSignature, SIGNATURES
from src.disk.filesystem import FilesystemNavigator
from src.disk.imager import DiskImager


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

    def test_empty_source(self, tmp_path) -> None:
        source = tmp_path / "empty.bin"
        source.write_bytes(b"")
        dest = tmp_path / "empty.dd"
        imager = DiskImager(str(source), str(dest))
        result = imager.acquire()
        assert result["bytes_copied"] == 0

    def test_large_block_acquisition(self, tmp_path) -> None:
        source = tmp_path / "large.bin"
        source.write_bytes(b"\xAB" * (4 * 1024 * 1024 + 13))  # > 4MB

        dest = tmp_path / "large.dd"
        imager = DiskImager(str(source), str(dest))
        result = imager.acquire()
        assert result["verified"] is True
        assert os.path.getsize(str(dest)) == os.path.getsize(str(source))

    def test_cancellation(self, tmp_path) -> None:
        source = tmp_path / "cancel_source.bin"
        source.write_bytes(b"\xBB" * (8 * 1024 * 1024))
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
        jpeg_data = b"\xff\xd8\xff" + b"\x00" * 100 + b"\xff\xd9"
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
        pdf_data = b"%PDF" + b"1.4 obj stream endobj" + b"\n%%EOF"
        image.write_bytes(pdf_data)

        output = tmp_path / "carved_pdf"
        carver = FileCarver(str(image), str(output))
        results = carver.carve("pdf")
        assert len(results) == 1
        assert results[0]["file_type"] == "PDF"

    def test_carve_zip(self, tmp_path) -> None:
        image = tmp_path / "zip_test.raw"
        # Minimal ZIP structure
        zip_data = b"PK\x03\x04" + b"\x00" * 26 + b"hello.txt" + b"content"
        eocd = b"PK\x05\x06" + b"\x00" * 16
        full = zip_data + eocd
        image.write_bytes(full)

        output = tmp_path / "carved_zip"
        carver = FileCarver(str(image), str(output))
        results = carver.carve("zip")
        assert len(results) >= 1

    def test_carve_multiple_types(self, tmp_path) -> None:
        image = tmp_path / "multi.raw"
        jpeg = b"\xff\xd8\xff" + b"\x00" * 50 + b"\xff\xd9"
        png_h = b"\x89PNG\r\n\x1a\n"
        png = png_h + b"IEND\x00\x00\x00\x00"
        image.write_bytes(jpeg + png)

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
        data[510:512] = b"\x55\xAA"
        image.write_bytes(data)
        nav = FilesystemNavigator(str(image))
        fs = nav.identify_filesystem()
        assert fs == "NTFS"

    def test_fat32_boot_sector(self, tmp_path) -> None:
        image = tmp_path / "fat32.img"
        data = bytearray(512)
        data[3:11] = b"FAT32   "
        data[510:512] = b"\x55\xAA"
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
        data = b"filename=\"report.pdf\" " * 10 + b"Content-Type: application/pdf"
        image.write_bytes(data)
        nav = FilesystemNavigator(str(image))
        entries = nav.list_directory("/")
        assert len(entries) >= 1

    def test_mbr_partition_table(self, tmp_path) -> None:
        image = tmp_path / "mbr.img"
        data = bytearray(512)
        data[510:512] = b"\x55\xAA"
        # Partition 1: type 0x07 (NTFS)
        data[446 + 4] = 0x07
        image.write_bytes(data)
        nav = FilesystemNavigator(str(image))
        fs = nav.identify_filesystem()
        assert fs == "NTFS"
