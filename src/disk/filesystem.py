"""Filesystem navigation on forensic disk images.

Provides read-only traversal of FAT, NTFS, and ext* filesystem structures
by parsing key on-disk data structures.
"""

from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class FileEntry:
    """Represents a file or directory entry in a filesystem."""

    name: str = ""
    path: str = ""
    size: int = 0
    is_directory: bool = False
    created: Optional[str] = None
    modified: Optional[str] = None
    accessed: Optional[str] = None
    permissions: str = ""
    inode: int = 0


class FilesystemNavigator:
    """Navigates filesystem structures within a disk image."""

    SUPPORTED_FS = {
        b"NTFS    ": "NTFS",
        b"FAT12   ": "FAT12",
        b"FAT16   ": "FAT16",
        b"FAT32   ": "FAT32",
        b"ext2    ": "ext2",
        b"ext3    ": "ext3",
        b"ext4    ": "ext4",
    }

    def __init__(self, image_path: str) -> None:
        if not os.path.isfile(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")
        self.image_path = image_path
        self._data: Optional[bytes] = None
        self._image_size = os.path.getsize(image_path)
        self._fs_type: Optional[str] = None
        self._byte_order: str = "<"  # little-endian default

    def _load(self) -> None:
        """Load the entire image into memory."""
        if self._data is not None:
            return
        with open(self.image_path, "rb") as f:
            self._data = f.read()

    def identify_filesystem(self) -> Optional[str]:
        """Identify the filesystem type from the boot sector."""
        self._load()
        if self._data is None:
            return None

        # Check MBR/VBR for OEM ID at offset 3
        for offset in [0, 512, 1024, 2048]:
            oem = self._data[offset + 3 : offset + 11]
            if oem in self.SUPPORTED_FS:
                self._fs_type = self.SUPPORTED_FS[oem]
                return self._fs_type

        # Check for ext* superblock at offset 1024
        ext_magic = (
            struct.unpack_from("<H", self._data, 1080)[0]
            if len(self._data) > 1082
            else 0
        )
        if ext_magic == 0xEF53:
            self._fs_type = self._detect_ext_version()
            return self._fs_type

        # Fallback: check partition table for known types
        part_type = self._check_partition_table()
        if part_type:
            self._fs_type = part_type
            return part_type

        return None

    def _detect_ext_version(self) -> str:
        """Detect ext2/ext3/ext4 from superblock features."""
        if self._data is None:
            return "ext2"
        feat_compat = struct.unpack_from("<I", self._data, 1084)[0]
        feat_incompat = struct.unpack_from("<I", self._data, 1088)[0]
        if feat_incompat & 0x02:  # Incompat feature: extents
            return "ext4"
        if feat_compat & 0x04:  # Compat feature: has journal
            return "ext3"
        return "ext2"

    def _check_partition_table(self) -> Optional[str]:
        """Check MBR partition table for known filesystem types."""
        if self._data is None or len(self._data) < 512:
            return None
        if self._data[510:512] != b"\x55\xaa":
            return None

        for i in range(4):
            offset = 446 + i * 16
            if offset + 16 > len(self._data):
                break
            part_type = self._data[offset + 4]
            type_map = {
                0x01: "FAT12",
                0x04: "FAT16",
                0x06: "FAT16B",
                0x07: "NTFS",
                0x0B: "FAT32",
                0x0C: "FAT32",
                0x83: "ext2/3/4",
            }
            if part_type in type_map:
                return type_map[part_type]
        return None

    def list_directory(self, path: str = "/") -> List[FileEntry]:
        """List directory contents at the given path.

        This reads filesystem structures directly from the image.
        For real images, this parses directory entries; for raw images
        it falls back to string-based file discovery.
        """
        self._load()
        if self._data is None:
            return []

        if self._fs_type == "NTFS":
            return self._list_ntfs(path)
        elif self._fs_type and self._fs_type.startswith("FAT"):
            return self._list_fat(path)
        elif self._fs_type and self._fs_type.startswith("ext"):
            return self._list_ext(path)
        else:
            return self._list_fallback(path)

    def _list_ntfs(self, path: str) -> List[FileEntry]:
        """List directory entries by scanning NTFS MFT records."""
        entries: List[FileEntry] = []
        if self._data is None:
            return entries

        # MFT is typically at cluster 0x04 - scan for FILE records
        mft_offset = 0
        if len(self._data) > 1024 * 1024 * 10:
            cluster_size = self._guess_cluster_size()
            mft_offset = 0x04 * cluster_size if cluster_size else 0

        offset = mft_offset
        record_count = 0
        while offset < len(self._data) - 1024 and record_count < 200:
            if self._data[offset : offset + 4] == b"FILE":
                try:
                    name = self._extract_ntfs_name(offset)
                    if name and name not in (
                        ".",
                        "..",
                        "$MFT",
                        "$MFTMirr",
                        "$LogFile",
                        "$Volume",
                        "$AttrDef",
                        "$Bitmap",
                        "$Boot",
                        "$BadClus",
                        "$Secure",
                        "$UpCase",
                        "$Extend",
                    ):
                        flags = struct.unpack_from("<H", self._data, offset + 0x16)[0]
                        is_dir = bool(flags & 0x01)
                        real_size = struct.unpack_from("<Q", self._data, offset + 0x30)[
                            0
                        ]
                        entries.append(
                            FileEntry(
                                name=name,
                                path=f"{path}{name}",
                                size=real_size,
                                is_directory=is_dir,
                                permissions="rw-r--r--",
                            )
                        )
                        record_count += 1
                except (struct.error, ValueError):
                    pass
                offset += 1024
            else:
                offset += 2

        return entries

    def _extract_ntfs_name(self, mft_offset: int) -> Optional[str]:
        """Extract the filename from an NTFS FILE record."""
        if self._data is None:
            return None
        try:
            attr_offset = struct.unpack_from("<H", self._data, mft_offset + 0x14)[0]
            pos = mft_offset + attr_offset
            while pos < mft_offset + 1024 - 24:
                attr_type = struct.unpack_from("<I", self._data, pos)[0]
                if attr_type == 0xFFFFFFFF:
                    break
                if attr_type == 0x30:  # $FILE_NAME
                    name_len = (
                        self._data[pos + 0x58] if pos + 0x58 < len(self._data) else 0
                    )
                    name_offset = pos + 0x5A
                    if name_len > 0 and name_offset + name_len * 2 <= len(self._data):
                        raw = self._data[name_offset : name_offset + name_len * 2]
                        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                attr_len = struct.unpack_from("<I", self._data, pos + 4)[0]
                if attr_len == 0:
                    break
                pos += attr_len
        except (struct.error, ValueError, IndexError):
            pass
        return None

    def _list_fat(self, path: str) -> List[FileEntry]:
        """List directory entries from a FAT filesystem."""
        entries: List[FileEntry] = []
        if self._data is None:
            return entries

        # Parse root directory entries starting at a known offset
        root_offset = self._find_fat_root_offset()
        offset = root_offset
        while offset < len(self._data) - 32:
            entry = self._data[offset : offset + 32]
            if entry[0] == 0x00:  # End of directory
                break
            if entry[0] == 0xE5 or entry[0] == 0x05:  # Deleted or special
                offset += 32
                continue
            if entry[0xB] == 0x0F:  # Long file name entry
                offset += 32
                continue

            attr = entry[0xB]
            name = self._parse_fat_name(entry)
            if name and name not in (".", ".."):
                size = struct.unpack_from("<I", entry, 0x1C)[0]
                entries.append(
                    FileEntry(
                        name=name,
                        path=f"{path}{name}",
                        size=size,
                        is_directory=bool(attr & 0x10),
                        created=self._parse_fat_datetime(entry, 0x10),
                        modified=self._parse_fat_datetime(entry, 0x16),
                        accessed=self._parse_fat_date(entry, 0x12),
                        permissions="rw-r--r--",
                    )
                )
            offset += 32

        return entries

    def _find_fat_root_offset(self) -> int:
        """Calculate root directory offset for FAT filesystems."""
        if self._data is None:
            return 0
        try:
            # BPB at offset 0
            bytes_per_sector = struct.unpack_from("<H", self._data, 0x0B)[0]
            sectors_per_cluster = self._data[0x0D]
            reserved_sectors = struct.unpack_from("<H", self._data, 0x0E)[0]
            num_fats = self._data[0x10]
            fat_size = struct.unpack_from("<I", self._data, 0x24)[0]  # FAT32
            if fat_size == 0:
                fat_size = struct.unpack_from("<H", self._data, 0x16)[0]  # FAT16
            root_entries = struct.unpack_from("<H", self._data, 0x11)[0]

            data_start = reserved_sectors + (num_fats * fat_size)
            if fat_size > 0x10000:  # FAT32
                root_cluster = struct.unpack_from("<I", self._data, 0x2C)[0]
                root_offset = (
                    data_start + (root_cluster - 2) * sectors_per_cluster
                ) * bytes_per_sector
            else:
                root_offset = data_start * bytes_per_sector

            return root_offset if root_offset < len(self._data) else 0
        except (struct.error, ValueError):
            return 0

    def _parse_fat_name(self, entry: bytes) -> str:
        """Parse 8.3 filename from a FAT directory entry."""
        try:
            name = entry[0:8].rstrip(b" ").decode("ascii", errors="replace")
            ext = entry[8:11].rstrip(b" ").decode("ascii", errors="replace")
            if ext:
                return f"{name}.{ext}"
            return name
        except (ValueError, UnicodeDecodeError):
            return ""

    def _parse_fat_datetime(self, entry: bytes, offset: int) -> Optional[str]:
        """Parse a FAT date+time entry (2 bytes date + 2 bytes time)."""
        try:
            date = struct.unpack_from("<H", entry, offset + 2)[0]
            time = struct.unpack_from("<H", entry, offset)[0]
            year = ((date >> 9) & 0x7F) + 1980
            month = (date >> 5) & 0x0F
            day = date & 0x1F
            hour = (time >> 11) & 0x1F
            minute = (time >> 5) & 0x3F
            second = (time & 0x1F) * 2
            dt = datetime(year, month, day, hour, minute, second)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (struct.error, ValueError):
            return None

    def _parse_fat_date(self, entry: bytes, offset: int) -> Optional[str]:
        """Parse a FAT date-only entry."""
        try:
            date = struct.unpack_from("<H", entry, offset)[0]
            year = ((date >> 9) & 0x7F) + 1980
            month = (date >> 5) & 0x0F
            day = date & 0x1F
            dt = datetime(year, month, day)
            return dt.strftime("%Y-%m-%d")
        except (struct.error, ValueError):
            return None

    def _list_ext(self, path: str) -> List[FileEntry]:
        """List directory entries from an ext2/3/4 filesystem."""
        entries: List[FileEntry] = []
        if self._data is None or len(self._data) < 2048:
            return entries

        try:
            inode_size = struct.unpack_from("<H", self._data, 0x58)[0] or 128
            block_size = 1024 << struct.unpack_from("<I", self._data, 0x18)[0]

            # Root inode (usually #2)
            root_inode_offset = 2048 + (2 - 1) * inode_size
            if self._data[root_inode_offset : root_inode_offset + 4] != b"\x00" * 4:
                # Read block pointers from root inode
                block_offset = root_inode_offset + 40  # direct block pointer 0
                for i in range(12):
                    block_ptr = struct.unpack_from(
                        "<I", self._data, block_offset + i * 4
                    )[0]
                    if block_ptr == 0:
                        continue
                    dir_block_offset = block_ptr * block_size
                    if dir_block_offset >= len(self._data):
                        continue
                    entries.extend(self._parse_ext_dir_block(dir_block_offset))
        except (struct.error, ValueError, IndexError) as e:
            logger.debug("ext listing error: %s", e)

        return entries

    def _parse_ext_dir_block(self, offset: int) -> List[FileEntry]:
        """Parse an ext* directory block for entries."""
        entries: List[FileEntry] = []
        if self._data is None:
            return entries

        pos = offset
        while pos < len(self._data) - 8:
            try:
                inode = struct.unpack_from("<I", self._data, pos)[0]
                rec_len = struct.unpack_from("<H", self._data, pos + 4)[0]
                name_len = self._data[pos + 6] if pos + 6 < len(self._data) else 0
                file_type = self._data[pos + 7] if pos + 7 < len(self._data) else 0

                if rec_len < 8 or name_len == 0 or inode == 0:
                    break

                name_bytes = self._data[pos + 8 : pos + 8 + name_len]
                name = name_bytes.decode("utf-8", errors="replace").rstrip("\x00")
                if name and name not in (".", ".."):
                    entries.append(
                        FileEntry(
                            name=name,
                            inode=inode,
                            is_directory=file_type == 2,
                            permissions=self._ext_permissions(inode),
                        )
                    )
                pos += rec_len
            except (struct.error, ValueError, IndexError):
                break

        return entries

    def _ext_permissions(self, inode: int) -> str:
        """Guess permissions string for an ext inode (simplified)."""
        return "rw-r--r--"

    def _guess_cluster_size(self) -> int:
        """Guess cluster size from NTFS BPB."""
        if self._data is None or len(self._data) < 16:
            return 4096
        try:
            bps = struct.unpack_from("<H", self._data, 0x0B)[0]
            spc = self._data[0x0D]
            return bps * spc
        except (struct.error, ValueError):
            return 4096

    def _list_fallback(self, path: str) -> List[FileEntry]:
        """Fallback: scan for file-like strings in the image."""
        entries: List[FileEntry] = []
        if self._data is None:
            return entries

        patterns = [
            b"Content-Type: application/",
            b'filename="',
            b"Filename: ",
        ]
        seen: Set[str] = set()
        for pattern in patterns:
            offset = 0
            while offset < len(self._data):
                pos = self._data.find(pattern, offset)
                if pos == -1:
                    break
                snippet = self._data[pos : pos + 100]
                for match in self._extract_filenames(snippet):
                    if match not in seen:
                        seen.add(match)
                        entries.append(
                            FileEntry(
                                name=match,
                                path=match,
                                size=0,
                                is_directory=False,
                            )
                        )
                offset = pos + 1
        return entries

    @staticmethod
    def _extract_filenames(data: bytes) -> List[str]:
        """Extract potential filenames from binary data."""
        names: List[str] = []
        try:
            text = data.decode("utf-8", errors="ignore")
            import re

            matches = re.findall(r"[\w\-\.]+\.\w{2,4}", text)
            names.extend(matches[:5])
        except Exception:
            pass
        return names
