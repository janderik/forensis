"""Disk imaging utility (dd-style acquisition).

Creates forensic bit-for-bit copies of storage media with
verifiable integrity via hash logging.
"""

from __future__ import annotations

import hashlib
import logging
import os
import struct
import sys
from datetime import datetime
from threading import Event, Thread
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class ImagingError(Exception):
    """Raised on imaging failures."""

    pass


class DiskImager:
    """Creates forensic disk images with hash verification."""

    BLOCK_SIZE = 4 * 1024 * 1024  # 4 MB blocks

    def __init__(
        self,
        source: str,
        destination: str,
        log_path: Optional[str] = None,
        verify: bool = True,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        self.source = source
        self.destination = destination
        self.log_path = log_path
        self.verify = verify
        self.progress_callback = progress_callback
        self._cancel = Event()
        self._source_size: int = 0
        self._bytes_read: int = 0
        self._hash_sha256 = hashlib.sha256()
        self._hash_md5 = hashlib.md5()

    @property
    def source_size(self) -> int:
        return self._source_size

    @property
    def bytes_read(self) -> int:
        return self._bytes_read

    def cancel(self) -> None:
        """Signal cancellation of an in-progress imaging operation."""
        self._cancel.set()

    def acquire(self) -> dict:
        """Execute the imaging acquisition.

        Returns:
            dict with acquisition metadata including hashes.

        Raises:
            ImagingError: on source/destination read/write failures.
            FileNotFoundError: if source does not exist.
        """
        if not os.path.exists(self.source):
            raise FileNotFoundError(f"Source not found: {self.source}")

        self._source_size = os.path.getsize(self.source)
        logger.info("Starting acquisition: %s -> %s (%d bytes)", self.source, self.destination, self._source_size)

        dest_dir = os.path.dirname(os.path.abspath(self.destination))
        if dest_dir and not os.path.exists(dest_dir):
            os.makedirs(dest_dir, exist_ok=True)

        start_time = datetime.utcnow()

        try:
            with open(self.source, "rb") as src, open(self.destination, "wb") as dst:
                while self._bytes_read < self._source_size and not self._cancel.is_set():
                    block = src.read(self.BLOCK_SIZE)
                    if not block:
                        break
                    dst.write(block)
                    self._hash_sha256.update(block)
                    self._hash_md5.update(block)
                    self._bytes_read += len(block)
                    if self.progress_callback:
                        self.progress_callback(self._bytes_read, self._source_size)
        except IOError as e:
            raise ImagingError(f"I/O error during acquisition: {e}")

        if self._cancel.is_set():
            logger.warning("Acquisition cancelled at %d/%d bytes", self._bytes_read, self._source_size)
            self._cleanup_partial()
            raise ImagingError("Acquisition cancelled by user")

        end_time = datetime.utcnow()
        sha256_hex = self._hash_sha256.hexdigest()
        md5_hex = self._hash_md5.hexdigest()

        result = {
            "source": self.source,
            "destination": self.destination,
            "source_size": self._source_size,
            "bytes_copied": self._bytes_read,
            "sha256": sha256_hex,
            "md5": md5_hex,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
            "verified": False,
        }

        if self.verify:
            result["verified"] = self._verify_image(sha256_hex, md5_hex)

        self._write_log(result)
        logger.info("Acquisition complete: SHA256=%s", sha256_hex)
        return result

    def _verify_image(self, expected_sha256: str, expected_md5: str) -> bool:
        """Verify the destination image matches expected hashes."""
        logger.info("Verifying image integrity...")
        try:
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            with open(self.destination, "rb") as f:
                while True:
                    block = f.read(self.BLOCK_SIZE)
                    if not block:
                        break
                    sha256.update(block)
                    md5.update(block)
            return sha256.hexdigest() == expected_sha256 and md5.hexdigest() == expected_md5
        except Exception as e:
            logger.error("Verification failed: %s", e)
            return False

    def _cleanup_partial(self) -> None:
        """Remove partially written destination file."""
        try:
            if os.path.exists(self.destination):
                os.remove(self.destination)
                logger.info("Removed partial destination: %s", self.destination)
        except OSError as e:
            logger.error("Failed to clean up partial image: %s", e)

    def _write_log(self, result: dict) -> None:
        """Write acquisition log if log_path is configured."""
        if not self.log_path:
            return
        try:
            log_dir = os.path.dirname(os.path.abspath(self.log_path))
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            with open(self.log_path, "a") as f:
                f.write(f"=== Forensic Acquisition Log ===\n")
                f.write(f"Timestamp: {datetime.utcnow().isoformat()}\n")
                f.write(f"Source: {result['source']}\n")
                f.write(f"Destination: {result['destination']}\n")
                f.write(f"Size: {result['source_size']} bytes\n")
                f.write(f"SHA256: {result['sha256']}\n")
                f.write(f"MD5: {result['md5']}\n")
                f.write(f"Verified: {result['verified']}\n")
                f.write(f"Duration: {result['duration_seconds']}s\n")
                f.write("=" * 40 + "\n")
        except IOError as e:
            logger.warning("Failed to write acquisition log: %s", e)

    @staticmethod
    def create_sparse(source: str, destination: str) -> dict:
        """Create a sparse image, skipping null blocks."""
        block_size = DiskImager.BLOCK_SIZE
        bytes_read = 0
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()

        source_size = os.path.getsize(source)
        with open(source, "rb") as src, open(destination, "wb") as dst:
            while bytes_read < source_size:
                block = src.read(block_size)
                if not block:
                    break
                sha256.update(block)
                md5.update(block)
                if block.strip(b"\x00"):
                    dst.write(block)
                else:
                    dst.write(b"\x00" * len(block))
                bytes_read += len(block)

        return {
            "source": source,
            "destination": destination,
            "source_size": source_size,
            "bytes_copied": bytes_read,
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest(),
        }
