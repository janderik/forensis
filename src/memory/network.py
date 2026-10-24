"""Network connection enumeration from memory dumps.

Scans memory dump data for network connection artifacts including
TCP and UDP endpoint information.
"""

from __future__ import annotations

import re
import struct
from typing import Dict, List, Optional


class NetworkConnections:
    """Extracts network connection information from a memory dump buffer."""

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        self._data = data
        self._size = len(data)

    def list_connections(self) -> List[Dict]:
        """Return a list of network connection dictionaries found in the dump."""
        connections: List[Dict] = []
        connections.extend(self._scan_tcp_structures())
        connections.extend(self._scan_ip_strings())
        return connections[:200]

    def _scan_tcp_structures(self) -> List[Dict]:
        """Scan for TCP endpoint structures using heuristics."""
        results: List[Dict] = []
        offset = 0
        stride = 8

        while offset < self._size - 128:
            try:
                local_ip_raw = self._data[offset : offset + 4]
                remote_ip_raw = self._data[offset + 4 : offset + 8]

                local_ip = self._format_ipv4(local_ip_raw)
                remote_ip = self._format_ipv4(remote_ip_raw)

                local_port = struct.unpack_from("<H", self._data, offset + 16)[0]
                remote_port = struct.unpack_from("<H", self._data, offset + 18)[0]

                state_byte = self._data[offset + 24] if offset + 24 < self._size else 0
                state = self._tcp_state(state_byte)

                if self._is_valid_port(local_port):
                    results.append(
                        {
                            "protocol": "TCP",
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "state": state,
                            "offset": hex(offset),
                        }
                    )
            except (struct.error, IndexError):
                pass
            offset += stride

        return results

    def _scan_ip_strings(self) -> List[Dict]:
        """Scan for IP:port string patterns in memory."""
        results: List[Dict] = []
        pattern = re.compile(rb"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})")

        for match in pattern.finditer(self._data):
            ip_str = match.group(1).decode("ascii", errors="ignore")
            port_str = match.group(2).decode("ascii", errors="ignore")
            try:
                port = int(port_str)
            except ValueError:
                continue

            parts = ip_str.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                results.append(
                    {
                        "protocol": "UNKNOWN",
                        "local_ip": ip_str,
                        "local_port": port,
                        "remote_ip": "",
                        "remote_port": 0,
                        "state": "UNKNOWN",
                        "offset": hex(match.start()),
                        "source": "string_pattern",
                    }
                )

        return results

    @staticmethod
    def _format_ipv4(raw: bytes) -> str:
        """Format 4 bytes as an IPv4 address string."""
        if len(raw) < 4:
            return "0.0.0.0"
        return ".".join(str(b) for b in raw[:4])

    @staticmethod
    def _is_valid_port(port: int) -> bool:
        """Check if port number is in valid range (1-65535)."""
        return 1 <= port <= 65535

    @staticmethod
    def _tcp_state(byte: int) -> str:
        """Map a TCP state byte to a human-readable state name."""
        states = {
            0: "CLOSED",
            1: "LISTEN",
            2: "SYN_SENT",
            3: "SYN_RECEIVED",
            4: "ESTABLISHED",
            5: "FIN_WAIT1",
            6: "FIN_WAIT2",
            7: "CLOSE_WAIT",
            8: "CLOSING",
            9: "LAST_ACK",
            10: "TIME_WAIT",
            12: "DELETE_TCB",
        }
        return states.get(byte, f"UNKNOWN ({byte})")
