"""File carving — signature-based recovery of deleted files from disk images.

Supports carving of JPEG, PNG, PDF, DOCX (ZIP-based), ZIP, and ELF files
by matching magic byte signatures and validating footer/structures.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class FileSignature:
    """Describes a file type's magic byte signature."""

    name: str
    extension: str
    header: bytes
    footer: Optional[bytes]
    min_size: int = 4
    max_size: int = 100 * 1024 * 1024  # 100 MB default


# Registry of supported file signatures with magic bytes
SIGNATURES: List[FileSignature] = [
    # min_size ~ smallest structurally valid file, so small thumbnails/icons are kept.
    FileSignature("JPEG", "jpg", b"\xff\xd8\xff", b"\xff\xd9", min_size=125),
    FileSignature(
        "PNG", "png", b"\x89PNG\r\n\x1a\n", b"IEND\xae\x42\x60\x82", min_size=67
    ),
    FileSignature("PDF", "pdf", b"%PDF", b"%%EOF", min_size=256),
    FileSignature("DOCX", "docx", b"PK\x03\x04", b"", min_size=4096),
    FileSignature("ZIP", "zip", b"PK\x03\x04", b"PK\x05\x06", min_size=98),
    FileSignature("ELF", "elf", b"\x7fELF", b"", min_size=64),
    FileSignature("GIF", "gif", b"GIF89a", b"\x00\x3b", min_size=64),
    FileSignature("GIF", "gif", b"GIF87a", b"\x00\x3b", min_size=64),
    FileSignature("RIFF", "avi", b"RIFF", b"", min_size=4096),
    FileSignature("BMP", "bmp", b"BM", b"", min_size=54),
]


class CarvingError(Exception):
    """Raised on carving failures."""

    pass


class FileCarver:
    """Carves files from a disk image using signature-based recovery."""

    def __init__(self, image_path: str, output_dir: str = "carved") -> None:
        if not os.path.isfile(image_path):
            raise FileNotFoundError(f"Image file not found: {image_path}")
        self.image_path = image_path
        self.output_dir = output_dir
        self._image_size = os.path.getsize(image_path)
        self._carved_count = 0
        self._total_size = 0

    @property
    def carved_count(self) -> int:
        return self._carved_count

    @property
    def total_size(self) -> int:
        return self._total_size

    def carve_all(self, types: Optional[List[str]] = None) -> List[Dict]:
        """Carve all supported file types from the image.

        Args:
            types: List of file extensions to carve (e.g. ['jpg', 'png']).
                   If None, all known types are carved.

        Returns:
            List of dicts with metadata for each recovered file.
        """
        sigs = self._filter_signatures(types)
        results: List[Dict] = []

        os.makedirs(self.output_dir, exist_ok=True)

        with open(self.image_path, "rb") as f:
            data = f.read()

        for sig in sigs:
            try:
                carved = self._carve_type(data, sig)
                results.extend(carved)
            except Exception as e:
                logger.warning("Error carving %s: %s", sig.name, e)

        self._carved_count = len(results)
        self._total_size = sum(r.get("size", 0) for r in results)
        return results

    def carve(self, extension: str) -> List[Dict]:
        """Carve a specific file type by extension."""
        return self.carve_all(types=[extension.lstrip(".").lower()])

    def _filter_signatures(self, types: Optional[List[str]]) -> List[FileSignature]:
        """Filter the signature registry to requested types."""
        if not types:
            return SIGNATURES.copy()
        normalized = {t.lower().lstrip(".") for t in types}
        return [s for s in SIGNATURES if s.extension.lower() in normalized]

    def _carve_type(self, data: bytes, sig: FileSignature) -> List[Dict]:
        """Carve all instances of a single file type from the data buffer."""
        results: List[Dict] = []
        offset = 0
        file_index = 0

        while offset < len(data):
            header_pos = data.find(sig.header, offset)
            if header_pos == -1:
                break

            end_pos = self._find_footer(data, header_pos, sig)
            if end_pos is None:
                offset = header_pos + 1
                continue

            file_data = data[header_pos:end_pos]
            file_size = len(file_data)

            if file_size < sig.min_size or file_size > sig.max_size:
                offset = header_pos + 1
                continue

            out_path = self._write_file(file_data, sig, file_index)
            results.append(
                {
                    "file_type": sig.name,
                    "extension": sig.extension,
                    "size": file_size,
                    "offset": hex(header_pos),
                    "end_offset": hex(end_pos),
                    "path": out_path,
                    "index": file_index,
                }
            )
            file_index += 1
            offset = end_pos  # end_pos is exclusive: the next file may start right here

        return results

    def _find_footer(
        self, data: bytes, start: int, sig: FileSignature
    ) -> Optional[int]:
        """Find the end of a file given its signature and start offset."""
        search_start = start + len(sig.header)

        if sig.footer:
            if sig.name == "PNG":
                # PNG: scan for IEND chunk
                pos = self._find_png_end(data, search_start)
            elif sig.name == "JPEG":
                pos = self._find_jpeg_end(data, search_start)
            elif sig.name == "PDF":
                pos = self._find_pdf_end(data, search_start)
            elif sig.name == "ZIP":
                pos = self._find_zip_end(data, search_start)
            else:
                pos = data.find(sig.footer, search_start)
                if pos != -1:
                    pos += len(sig.footer)
        else:
            # No footer: use heuristic max size or next header
            pos = self._find_next_header(data, search_start, sig)
            if pos is None:
                pos = min(search_start + sig.max_size, len(data))

        if pos is None or pos <= start:
            return None
        return pos

    def _find_jpeg_end(self, data: bytes, start: int) -> Optional[int]:
        """Find JPEG end marker (FF D9), robust to trailing data."""
        pos = data.find(b"\xff\xd9", start)
        if pos != -1:
            return pos + 2  # Include the marker
        return None

    def _find_png_end(self, data: bytes, start: int) -> Optional[int]:
        """Find PNG IEND chunk position."""
        pos = data.find(b"IEND", start)
        if pos != -1 and pos + 8 <= len(data):
            return pos + 8  # IEND + 4 bytes CRC
        return None

    def _find_pdf_end(self, data: bytes, start: int) -> Optional[int]:
        """Find PDF end-of-file marker."""
        pos = data.find(b"%%EOF", start)
        if pos != -1:
            return pos + 5
        # Try with whitespace variations
        pos = data.find(b"%%EOF\n", start)
        if pos != -1:
            return pos + 6
        pos = data.find(b"%%EOF\r\n", start)
        if pos != -1:
            return pos + 7
        return None

    def _find_zip_end(self, data: bytes, start: int) -> Optional[int]:
        """Find ZIP End of Central Directory record."""
        # EOCD signature: PK\x05\x06
        eocd = data.find(b"PK\x05\x06", start)
        if eocd != -1 and eocd + 22 <= len(data):
            return eocd + 22
        # Try central directory end
        eocd64 = data.find(b"PK\x06\x06", start)
        if eocd64 != -1:
            return eocd64 + 56
        return None

    def _find_next_header(
        self, data: bytes, start: int, sig: FileSignature
    ) -> Optional[int]:
        """Find the next known file header after start position."""
        best = None
        for other in SIGNATURES:
            if other.header == sig.header and other.extension == sig.extension:
                continue
            pos = data.find(other.header, start)
            if pos != -1 and (best is None or pos < best):
                best = pos
        return best

    def _write_file(self, file_data: bytes, sig: FileSignature, index: int) -> str:
        """Write carved file data to the output directory."""
        filename = f"{sig.name.lower()}_{index:04d}.{sig.extension}"
        out_path = os.path.join(self.output_dir, filename)
        with open(out_path, "wb") as f:
            f.write(file_data)
        logger.debug("Carved %s (%d bytes) -> %s", filename, len(file_data), out_path)
        return out_path
