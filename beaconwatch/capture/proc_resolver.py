"""Resolve network connections to PIDs/process names via /proc walking."""

from __future__ import annotations

import asyncio
import os
import re
import time
from pathlib import Path
from typing import NamedTuple


_CACHE_TTL_SECONDS = 5.0
_RETRY_COUNT = 3
_RETRY_DELAY_SECONDS = 0.015  # 15ms

# Hex-encoded inode in /proc/net/* files
_PROC_NET_FILES = {
    "tcp": "/proc/net/tcp",
    "tcp6": "/proc/net/tcp6",
    "udp": "/proc/net/udp",
    "udp6": "/proc/net/udp6",
}


class _CacheEntry(NamedTuple):
    pid: int
    name: str
    path: str
    cached_at: float


class ProcResolver:
    def __init__(self) -> None:
        # Cache: (proto_family, src_port) → _CacheEntry
        self._cache: dict[tuple[str, int], _CacheEntry] = {}

    def resolve(
        self, proto: str, src_port: int
    ) -> tuple[int, str, str] | None:
        """
        Resolve (proto, src_port) to (pid, process_name, process_path).
        Returns None if resolution fails (no crash — logged by caller).
        """
        proto_norm = proto.lower().replace("6", "")  # "tcp6" → "tcp"
        cache_key = (proto_norm, src_port)

        cached = self._cache.get(cache_key)
        if cached is not None and time.monotonic() - cached.cached_at < _CACHE_TTL_SECONDS:
            return (cached.pid, cached.name, cached.path)

        result = self._resolve_with_retry(proto_norm, src_port)
        if result is not None:
            pid, name, path = result
            self._cache[cache_key] = _CacheEntry(
                pid=pid, name=name, path=path, cached_at=time.monotonic()
            )
        return result

    def _resolve_with_retry(
        self, proto: str, src_port: int
    ) -> tuple[int, str, str] | None:
        for attempt in range(_RETRY_COUNT):
            result = self._do_resolve(proto, src_port)
            if result is not None:
                return result
            if attempt < _RETRY_COUNT - 1:
                time.sleep(_RETRY_DELAY_SECONDS)
        return None

    def _do_resolve(
        self, proto: str, src_port: int
    ) -> tuple[int, str, str] | None:
        inode = self._find_inode(proto, src_port)
        if inode is None:
            return None

        return self._inode_to_process(inode)

    def _find_inode(self, proto: str, src_port: int) -> str | None:
        """Walk /proc/net/tcp[6]/udp[6] to find the socket inode for src_port."""
        candidates = [proto, proto + "6"] if proto in ("tcp", "udp") else [proto]

        for variant in candidates:
            net_file = _PROC_NET_FILES.get(variant)
            if net_file is None:
                continue
            inode = _parse_proc_net(net_file, src_port)
            if inode is not None:
                return inode

        return None

    def _inode_to_process(self, inode: str) -> tuple[int, str, str] | None:
        """Walk /proc/<pid>/fd/* to find which process owns the socket inode."""
        inode_str = f"socket:[{inode}]"
        target_link = f"socket:[{inode}]"

        try:
            proc_dirs = os.listdir("/proc")
        except OSError:
            return None

        for entry in proc_dirs:
            if not entry.isdigit():
                continue
            pid = int(entry)
            fd_dir = f"/proc/{pid}/fd"

            try:
                fds = os.listdir(fd_dir)
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                # Other users' processes may not be readable without root
                continue

            for fd in fds:
                fd_path = f"{fd_dir}/{fd}"
                try:
                    link_target = os.readlink(fd_path)
                except (OSError, PermissionError):
                    continue

                if link_target == target_link:
                    name, path = _get_process_info(pid)
                    return (pid, name, path)

        return None

    def invalidate_port(self, proto: str, src_port: int) -> None:
        key = (proto.lower().replace("6", ""), src_port)
        self._cache.pop(key, None)


def _parse_proc_net(filepath: str, src_port: int) -> str | None:
    """
    Parse /proc/net/tcp[6]/udp[6] to find the inode for a given local port.
    Format: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
    Local address is encoded as hex: 0100007F:0035 (little-endian IP:port)
    """
    port_hex = f"{src_port:04X}"

    try:
        with open(filepath, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local_addr = parts[1]
                inode = parts[9]

                # local_addr format: "HEXIP:HEXPORT"
                if ":" not in local_addr:
                    continue
                _, local_port_hex = local_addr.rsplit(":", 1)
                if local_port_hex.upper() == port_hex:
                    try:
                        int(inode)  # validate it's numeric
                        return inode
                    except ValueError:
                        continue
    except (OSError, IOError, PermissionError):
        return None

    return None


def _get_process_info(pid: int) -> tuple[str, str]:
    """Return (process_name, process_path) for a PID."""
    # Try to read the exe symlink for the full path
    exe_path = f"/proc/{pid}/exe"
    path = ""
    try:
        path = os.readlink(exe_path)
        # Path may have " (deleted)" suffix if binary was replaced
        path = path.replace(" (deleted)", "").strip()
    except (OSError, PermissionError, FileNotFoundError):
        pass

    # Read the process name from /proc/<pid>/comm (short name, max 15 chars)
    name = ""
    comm_path = f"/proc/{pid}/comm"
    try:
        with open(comm_path, "r") as f:
            name = f.read().strip()
    except (OSError, PermissionError, FileNotFoundError):
        # Fall back to extracting name from path
        if path:
            name = Path(path).name

    if not name and path:
        name = Path(path).name

    return (name, path)
