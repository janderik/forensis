"""Multi-algorithm hashing for forensic evidence files.

Supports SHA-256, SHA-1, and MD5 with output in standard formats
including hash sets and per-algorithm listings.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)


@dataclass
class HashResult:
    """Container for hash computation results."""

    file_path: str = ""
    file_size: int = 0
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    algorithm: str = "sha256"


class HashingError(Exception):
    """Raised on hashing failures."""

    pass


class Hasher:
    """Computes cryptographic hashes of evidence files."""

    BLOCK_SIZE = 64 * 1024  # 64 KB

    SUPPORTED_ALGORITHMS = {"sha256", "sha1", "md5"}

    def __init__(self, file_path: str) -> None:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)

    def hash_all(self) -> HashResult:
        """Compute SHA-256, SHA-1, and MD5 hashes."""
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()

        try:
            with open(self.file_path, "rb") as f:
                while True:
                    block = f.read(self.BLOCK_SIZE)
                    if not block:
                        break
                    sha256.update(block)
                    sha1.update(block)
                    md5.update(block)
        except IOError as e:
            raise HashingError(f"Error reading {self.file_path}: {e}")

        return HashResult(
            file_path=self.file_path,
            file_size=self.file_size,
            sha256=sha256.hexdigest(),
            sha1=sha1.hexdigest(),
            md5=md5.hexdigest(),
        )

    def hash_single(self, algorithm: str = "sha256") -> HashResult:
        """Compute a single algorithm hash.

        Args:
            algorithm: One of 'sha256', 'sha1', 'md5'.

        Returns:
            HashResult with the requested algorithm populated.
        """
        algo = algorithm.lower()
        if algo not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm: {algorithm}. Supported: {self.SUPPORTED_ALGORITHMS}"
            )

        hasher_fn = getattr(hashlib, algo.replace("-", ""))()
        try:
            with open(self.file_path, "rb") as f:
                while True:
                    block = f.read(self.BLOCK_SIZE)
                    if not block:
                        break
                    hasher_fn.update(block)
        except IOError as e:
            raise HashingError(f"Error reading {self.file_path}: {e}")

        result = HashResult(
            file_path=self.file_path,
            file_size=self.file_size,
            algorithm=algo,
        )
        setattr(result, algo, hasher_fn.hexdigest())
        return result

    def verify_hash(self, expected_hash: str, algorithm: str = "sha256") -> bool:
        """Verify a file against an expected hash.

        Args:
            expected_hash: The hex digest to compare against.
            algorithm: Hash algorithm to use.

        Returns:
            True if hashes match, False otherwise.
        """
        result = self.hash_single(algorithm)
        actual = getattr(result, algorithm.lower(), "")
        return actual.lower() == expected_hash.lower()

    @staticmethod
    def hash_directory(directory: str, algorithm: str = "sha256") -> Dict[str, str]:
        """Recursively hash all files in a directory.

        Args:
            directory: Path to directory.
            algorithm: Hash algorithm to use.

        Returns:
            Dict mapping relative file paths to hex digests.

        Raises:
            FileNotFoundError: if directory does not exist.
        """
        if not os.path.isdir(directory):
            raise FileNotFoundError(f"Directory not found: {directory}")

        results: Dict[str, str] = {}
        for root, _dirs, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, directory)
                try:
                    hasher = Hasher(fpath)
                    result = hasher.hash_single(algorithm)
                    digest = getattr(result, algorithm.lower(), "")
                    results[rel_path] = digest
                except (IOError, HashingError) as e:
                    logger.warning("Failed to hash %s: %s", rel_path, e)
                    results[rel_path] = f"ERROR: {e}"
        return results

    @staticmethod
    def export_hashset(
        results: List[HashResult],
        output_path: str,
        format: str = "hashset",
    ) -> None:
        """Export hash results in standard format.

        Args:
            results: List of HashResult objects.
            output_path: Path to write output file.
            format: 'hashset' (NSRL-style) or 'csv'.
        """
        with open(output_path, "w", encoding="utf-8") as f:
            if format == "csv":
                f.write("File,Size,SHA256,SHA1,MD5\n")
                for r in results:
                    f.write(
                        f"{r.file_path},{r.file_size},{r.sha256},{r.sha1},{r.md5}\n"
                    )
            else:
                # NSRL-style hash set
                f.write("# Forensis Hash Set\n")
                f.write(f"# Generated: {datetime.utcnow().isoformat()}\n")
                f.write("# Format: algorithm:hash  file_path\n")
                for r in results:
                    if r.sha256:
                        f.write(f"sha256:{r.sha256}  {r.file_path}\n")
                    if r.sha1:
                        f.write(f"sha1:{r.sha1}  {r.file_path}\n")
                    if r.md5:
                        f.write(f"md5:{r.md5}  {r.file_path}\n")
        logger.info("Exported %d hash results to %s", len(results), output_path)
