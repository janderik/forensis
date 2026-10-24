"""High-level memory analysis orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .network import NetworkConnections
from .processes import ProcessList


@dataclass
class MemoryAnalysisResult:
    """Container for full memory analysis results."""

    processes: List[Dict] = field(default_factory=list)
    connections: List[Dict] = field(default_factory=list)
    modules: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class MemoryAnalyzer:
    """Orchestrates memory analysis across process, network, and module enumeration."""

    def __init__(self, dump_path: str) -> None:
        self.dump_path = dump_path
        self._data: Optional[bytes] = None
        self._size: int = 0

    def _load_dump(self) -> None:
        """Load the memory dump file into memory with read-only access."""
        if self._data is not None:
            return
        try:
            with open(self.dump_path, "rb") as f:
                self._data = f.read()
            self._size = len(self._data)
        except FileNotFoundError:
            raise FileNotFoundError(f"Memory dump not found: {self.dump_path}")
        except PermissionError:
            raise PermissionError(f"Permission denied reading: {self.dump_path}")
        except Exception as e:
            raise IOError(f"Failed to load memory dump: {e}")

    def analyze_all(self) -> MemoryAnalysisResult:
        """Run all analyses and return combined results."""
        self._load_dump()
        result = MemoryAnalysisResult()

        try:
            pl = ProcessList(self._data)
            result.processes = pl.list_processes()
        except Exception as e:
            result.errors.append(f"Process analysis error: {e}")

        try:
            nc = NetworkConnections(self._data)
            result.connections = nc.list_connections()
        except Exception as e:
            result.errors.append(f"Network analysis error: {e}")

        try:
            result.modules = self._enumerate_modules()
        except Exception as e:
            result.errors.append(f"Module enumeration error: {e}")

        return result

    def analyze_processes(self) -> List[Dict]:
        """Run process analysis only."""
        self._load_dump()
        pl = ProcessList(self._data)
        return pl.list_processes()

    def analyze_network(self) -> List[Dict]:
        """Run network connection analysis only."""
        self._load_dump()
        nc = NetworkConnections(self._data)
        return nc.list_connections()

    def _enumerate_modules(self) -> List[Dict]:
        """Enumerate loaded kernel/driver modules from dump data."""
        modules: List[Dict] = []
        if self._data is None:
            return modules

        offset = 0
        module_signatures = [
            (b"MZ", "Portable Executable"),
            (b"\x7fELF", "ELF Binary"),
        ]

        chunk_size = 1024 * 1024
        while offset < self._size:
            chunk = self._data[offset : offset + chunk_size]
            for sig, desc in module_signatures:
                pos = chunk.find(sig)
                while pos != -1:
                    abs_pos = offset + pos
                    modules.append(
                        {
                            "offset": hex(abs_pos),
                            "signature": sig.hex(),
                            "description": f"Potential {desc} module",
                            "size": self._size - abs_pos,
                        }
                    )
                    pos = chunk.find(sig, pos + 1)
            offset += chunk_size

        return modules
