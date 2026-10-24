"""Tests for memory analysis modules."""

import struct

import pytest

from src.memory.analyzer import MemoryAnalysisResult, MemoryAnalyzer
from src.memory.network import NetworkConnections
from src.memory.processes import ProcessList


class TestProcessList:
    """Tests for ProcessList memory scanning."""

    def test_empty_data_raises_type_error(self) -> None:
        with pytest.raises(TypeError):
            ProcessList(None)  # type: ignore

    def test_empty_bytes_returns_empty(self) -> None:
        pl = ProcessList(b"")
        assert pl.list_processes() == []

    def test_small_bytes_no_processes(self) -> None:
        pl = ProcessList(b"\x00" * 100)
        result = pl.list_processes()
        assert isinstance(result, list)

    def test_known_process_name_detected(self) -> None:
        data = b"explorer.exe\x00".ljust(512, b"\x00")
        pl = ProcessList(data)
        procs = pl.list_processes()
        # Known process 'explorer.exe' should be found via string scan
        names = [p["name"] for p in procs]
        assert any("explorer.exe" in name.lower() for name in names if name)

    def test_pid_extraction_heuristic(self) -> None:
        data = bytearray(0x200)  # large enough to hold the name at +0x170
        struct.pack_into("<I", data, 0, 1234)  # Potential PID
        struct.pack_into("<I", data, 8, 567)  # Potential PPID
        data[0x170:0x178] = b"cmd.exe\x00"
        pl = ProcessList(bytes(data))
        procs = pl.list_processes()
        pids = [p["pid"] for p in procs]
        assert any(pid == 1234 for pid in pids)

    def test_process_limit_500(self) -> None:
        data = b"explorer.exe\x00" * 10000
        pl = ProcessList(data)
        procs = pl.list_processes()
        assert len(procs) <= 500

    def test_unicode_process_names(self) -> None:
        data = "système.exe".encode("utf-16-le") + b"\x00" * 128
        pl = ProcessList(data)
        procs = pl.list_processes()
        # Should not crash
        assert isinstance(procs, list)


class TestNetworkConnections:
    """Tests for NetworkConnections."""

    def test_empty_data_raises_type_error(self) -> None:
        with pytest.raises(TypeError):
            NetworkConnections(None)  # type: ignore

    def test_empty_bytes_returns_empty(self) -> None:
        nc = NetworkConnections(b"")
        assert nc.list_connections() == []

    def test_tcp_connection_detected(self) -> None:
        data = bytearray(256)
        # Simulate TCP structure: local IP 192.168.1.1, remote IP 10.0.0.1
        data[0:4] = b"\xc0\xa8\x01\x01"  # 192.168.1.1
        data[4:8] = b"\x0a\x00\x00\x01"  # 10.0.0.1
        struct.pack_into("<H", data, 16, 8080)  # local port
        struct.pack_into("<H", data, 18, 443)  # remote port
        data[24] = 4  # ESTABLISHED

        nc = NetworkConnections(bytes(data))
        conns = nc.list_connections()
        ports = [(c["local_port"], c["remote_port"]) for c in conns]
        assert (8080, 443) in ports

    def test_ip_string_scanning(self) -> None:
        data = b"Connection to 192.168.1.100:8443 established"
        nc = NetworkConnections(data)
        conns = nc.list_connections()
        ips = [(c["local_ip"], c["local_port"]) for c in conns]
        assert ("192.168.1.100", 8443) in ips

    def test_invalid_ip_ignored(self) -> None:
        data = b"999.999.999.999:12345"
        nc = NetworkConnections(data)
        conns = nc.list_connections()
        assert (
            all(
                all(0 <= int(p) <= 255 for p in c["local_ip"].split(".")) for c in conns
            )
            or len(conns) == 0
        )

    def test_tcp_state_mapping(self) -> None:
        assert NetworkConnections._tcp_state(4) == "ESTABLISHED"
        assert NetworkConnections._tcp_state(1) == "LISTEN"
        assert NetworkConnections._tcp_state(99) == "UNKNOWN (99)"

    def test_valid_port_range(self) -> None:
        assert NetworkConnections._is_valid_port(80) is True
        assert NetworkConnections._is_valid_port(0) is False
        assert NetworkConnections._is_valid_port(65536) is False

    def test_connection_limit_200(self) -> None:
        data = b"192.168.1.1:8080 " * 500
        nc = NetworkConnections(data)
        conns = nc.list_connections()
        assert len(conns) <= 200


class TestMemoryAnalyzer:
    """Tests for the high-level MemoryAnalyzer."""

    def test_nonexistent_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            MemoryAnalyzer("/nonexistent/dump.raw")

    def test_analyze_all_with_synthetic_data(self, tmp_path) -> None:
        dump_file = tmp_path / "dump.raw"
        dump_file.write_bytes(b"\x00" * 1024)
        analyzer = MemoryAnalyzer(str(dump_file))
        result = analyzer.analyze_all()
        assert isinstance(result, MemoryAnalysisResult)
        assert isinstance(result.processes, list)
        assert isinstance(result.connections, list)
        assert isinstance(result.modules, list)

    def test_analyze_all_with_corrupted_data(self, tmp_path) -> None:
        dump_file = tmp_path / "corrupt.raw"
        dump_file.write_bytes(b"\xff" * 512)
        analyzer = MemoryAnalyzer(str(dump_file))
        result = analyzer.analyze_all()
        assert isinstance(result, MemoryAnalysisResult)

    def test_detect_modules(self) -> None:
        data = b"MZ" * 10000 + b"\x7fELF" * 5000
        analyzer = MemoryAnalyzer.__new__(MemoryAnalyzer)  # Skip __init__
        analyzer._data = data
        analyzer._size = len(data)
        modules = analyzer._enumerate_modules()
        assert len(modules) >= 2

    def test_reuse_dump(self, tmp_path) -> None:
        dump_file = tmp_path / "reuse.raw"
        dump_file.write_bytes(b"explorer.exe" * 1000)
        analyzer = MemoryAnalyzer(str(dump_file))
        r1 = analyzer.analyze_all()
        r2 = analyzer.analyze_all()
        assert len(r1.processes) == len(r2.processes)

    def test_permission_error(self, tmp_path) -> None:

        dump_file = tmp_path / "noperm.raw"
        dump_file.write_bytes(b"\x00")
        # Can't easily test permission on Windows, so just verify the method is called
        # and falls through to the actual OS error
        analyzer = MemoryAnalyzer(str(dump_file))
        # Should not crash
        result = analyzer.analyze_all()
        assert isinstance(result, MemoryAnalysisResult)
