"""
Conntrack event subscription — monitors kernel connection tracking via netlink.

Two backends, auto-selected:
  1. pyroute2 (preferred): direct netlink via NFLOG/conntrack netlink socket.
     Low latency, no subprocess, but requires pyroute2 >= 0.7 with nfnetlink support.
  2. conntrack subprocess (fallback): spawns `conntrack -E` and parses text output.
     More portable, slightly higher latency, requires conntrack-tools installed.

Both require root or CAP_NET_ADMIN.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Callable

from .connection import Connection
from .proc_resolver import ProcResolver


# RFC1918 / private networks for outbound filtering
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "169.254.",
)


def _check_permissions() -> None:
    """Raise PermissionError with a helpful message if we lack root/CAP_NET_ADMIN."""
    import os
    if os.geteuid() != 0:
        # Check for CAP_NET_ADMIN capability
        try:
            with open("/proc/self/status") as f:
                content = f.read()
            # CapEff line contains effective capabilities as a hex bitmask
            for line in content.splitlines():
                if line.startswith("CapEff:"):
                    cap_eff = int(line.split(":")[1].strip(), 16)
                    cap_net_admin_bit = 1 << 12  # CAP_NET_ADMIN = 12
                    if cap_eff & cap_net_admin_bit:
                        return  # Have CAP_NET_ADMIN, proceed
        except (OSError, ValueError):
            pass

        raise PermissionError(
            "beaconwatch requires root or CAP_NET_ADMIN to read conntrack events.\n"
            "Try one of:\n"
            "  sudo beaconwatch daemon\n"
            "  sudo setcap cap_net_admin+ep $(which beaconwatch)"
        )


def _is_outbound_private(dst_ip: str) -> bool:
    """Return True if dst_ip is a private/loopback address."""
    try:
        addr = ipaddress.ip_address(dst_ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


# ── pyroute2 backend ──────────────────────────────────────────────────────────

def _try_import_pyroute2() -> bool:
    try:
        from pyroute2 import NFCTSocket  # type: ignore[import]
        return True
    except ImportError:
        return False
    except Exception:
        return False


class _Pyroute2Backend:
    """
    Conntrack event listener via pyroute2's NFCTSocket.
    Subscribes to NFCT_MSG_NEW and NFCT_MSG_DESTROY events.
    """

    def __init__(
        self,
        callback: Callable[[Connection], None],
        resolver: ProcResolver,
        include_lan: bool = False,
    ) -> None:
        self._callback = callback
        self._resolver = resolver
        self._include_lan = include_lan
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._listen_loop(), name="conntrack-pyroute2")

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _listen_loop(self) -> None:
        from pyroute2 import NFCTSocket  # type: ignore[import]
        import errno

        sock = NFCTSocket()
        try:
            sock.peyote(groups=0x1)  # subscribe to all conntrack events
        except Exception:
            # Older pyroute2 API
            pass

        loop = asyncio.get_event_loop()

        while self._running:
            try:
                # Non-blocking receive with asyncio
                data = await loop.run_in_executor(None, self._recv_one, sock)
                if data is not None:
                    self._callback(data)
            except asyncio.CancelledError:
                break
            except OSError as exc:
                if exc.errno in (errno.EINTR, errno.EAGAIN):
                    await asyncio.sleep(0.01)
                else:
                    raise
            except Exception:
                # Parse errors on individual events — skip, don't crash
                await asyncio.sleep(0.01)
        sock.close()

    def _recv_one(self, sock) -> Connection | None:
        try:
            msg_list = sock.get()
            if not msg_list:
                return None
        except Exception:
            return None

        for msg in msg_list:
            conn = self._parse_nfct_msg(msg)
            if conn is not None:
                return conn
        return None

    def _parse_nfct_msg(self, msg) -> Connection | None:
        try:
            attrs = dict(msg["attrs"])
            tuple_orig = dict(attrs.get("CTA_TUPLE_ORIG", {}).get("attrs", []) or [])
            tuple_ip = dict(tuple_orig.get("CTA_TUPLE_IP", {}).get("attrs", []) or [])
            tuple_proto_attr = dict(tuple_orig.get("CTA_TUPLE_PROTO", {}).get("attrs", []) or [])

            dst_ip = tuple_ip.get("CTA_IP_V4_DST") or tuple_ip.get("CTA_IP_V6_DST")
            src_ip = tuple_ip.get("CTA_IP_V4_SRC") or tuple_ip.get("CTA_IP_V6_SRC")
            if not dst_ip or not src_ip:
                return None

            # Filter private destinations unless include_lan is set
            if not self._include_lan and _is_outbound_private(dst_ip):
                return None
            if _is_outbound_private("127.0.0.1"):  # loopback always excluded
                pass
            try:
                dst_addr = ipaddress.ip_address(dst_ip)
                if dst_addr.is_loopback:
                    return None
            except ValueError:
                return None

            proto_num = tuple_proto_attr.get("CTA_PROTO_NUM", 0)
            proto = "tcp" if proto_num == 6 else ("udp" if proto_num == 17 else None)
            if proto is None:
                return None

            src_port = tuple_proto_attr.get("CTA_PROTO_SRC_PORT", 0)
            dst_port = tuple_proto_attr.get("CTA_PROTO_DST_PORT", 0)

            msg_type = msg.get("event", "")
            state = "new" if "NEW" in str(msg_type).upper() else "closed"

            bytes_sent = None
            bytes_recv = None
            if state == "closed":
                counters_orig = attrs.get("CTA_COUNTERS_ORIG", {})
                counters_reply = attrs.get("CTA_COUNTERS_REPLY", {})
                if counters_orig:
                    co = dict(counters_orig.get("attrs", []) or [])
                    bytes_sent = co.get("CTA_COUNTERS_BYTES")
                if counters_reply:
                    cr = dict(counters_reply.get("attrs", []) or [])
                    bytes_recv = cr.get("CTA_COUNTERS_BYTES")

            # Resolve process
            pid: int | None = None
            process_name: str | None = None
            process_path: str | None = None
            resolved = self._resolver.resolve(proto, src_port)
            if resolved is not None:
                pid, process_name, process_path = resolved

            return Connection(
                timestamp=datetime.now(tz=timezone.utc),
                proto=proto,
                src_ip=str(src_ip),
                src_port=src_port,
                dst_ip=str(dst_ip),
                dst_port=dst_port,
                pid=pid,
                process_name=process_name,
                process_path=process_path,
                bytes_sent=bytes_sent,
                bytes_recv=bytes_recv,
                state=state,
            )
        except (KeyError, TypeError, AttributeError):
            return None


# ── conntrack subprocess backend ──────────────────────────────────────────────

# conntrack -E output examples:
#     [NEW] tcp      6 120 SYN_SENT src=192.168.1.5 dst=93.184.216.34 sport=54321 dport=443 ...
#     [DESTROY] tcp  6 120 TIME_WAIT src=192.168.1.5 dst=93.184.216.34 sport=54321 dport=443 ...

_CT_LINE_RE = re.compile(
    r"\[(\w+)\]\s+(\w+)\s+\d+\s+\d+(?:\s+\w+)?\s+"
    r"src=([\d\.:a-fA-F]+)\s+dst=([\d\.:a-fA-F]+)\s+sport=(\d+)\s+dport=(\d+)"
    r"(?:.*?bytes=(\d+))?(?:.*?bytes=(\d+))?"
)


class _SubprocessBackend:
    """
    Conntrack event listener via `conntrack -E` subprocess output.
    Fallback when pyroute2 NFCTSocket is unavailable.
    """

    def __init__(
        self,
        callback: Callable[[Connection], None],
        resolver: ProcResolver,
        include_lan: bool = False,
    ) -> None:
        self._callback = callback
        self._resolver = resolver
        self._include_lan = include_lan
        self._running = False
        self._task: asyncio.Task | None = None
        self._proc: asyncio.subprocess.Process | None = None

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._listen_loop(), name="conntrack-subprocess")

    async def stop(self) -> None:
        self._running = False
        if self._proc is not None:
            try:
                self._proc.terminate()
                await asyncio.sleep(0.2)
                self._proc.kill()
            except ProcessLookupError:
                pass
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _listen_loop(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            "conntrack",
            "-E",
            "-p",
            "tcp,udp",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        assert self._proc.stdout is not None
        while self._running:
            try:
                line_bytes = await self._proc.stdout.readline()
            except asyncio.CancelledError:
                break

            if not line_bytes:
                # EOF — conntrack exited
                await asyncio.sleep(1.0)
                break

            line = line_bytes.decode(errors="replace").strip()
            conn = self._parse_line(line)
            if conn is not None:
                self._callback(conn)

    def _parse_line(self, line: str) -> Connection | None:
        m = _CT_LINE_RE.search(line)
        if m is None:
            return None

        event_type = m.group(1).upper()    # NEW or DESTROY
        proto = m.group(2).lower()         # tcp or udp
        src_ip = m.group(3)
        dst_ip = m.group(4)
        src_port = int(m.group(5))
        dst_port = int(m.group(6))
        bytes_sent_str = m.group(7)
        bytes_recv_str = m.group(8)

        if proto not in ("tcp", "udp"):
            return None

        # Filter loopback always
        try:
            if ipaddress.ip_address(dst_ip).is_loopback:
                return None
        except ValueError:
            return None

        if not self._include_lan and _is_outbound_private(dst_ip):
            return None

        state = "new" if event_type == "NEW" else "closed"
        bytes_sent: int | None = int(bytes_sent_str) if bytes_sent_str else None
        bytes_recv: int | None = int(bytes_recv_str) if bytes_recv_str else None

        pid: int | None = None
        process_name: str | None = None
        process_path: str | None = None
        resolved = self._resolver.resolve(proto, src_port)
        if resolved is not None:
            pid, process_name, process_path = resolved

        return Connection(
            timestamp=datetime.now(tz=timezone.utc),
            proto=proto,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            pid=pid,
            process_name=process_name,
            process_path=process_path,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            state=state,
        )


# ── Public interface ──────────────────────────────────────────────────────────

class ConntrackMonitor:
    """
    High-level conntrack event monitor.
    Auto-selects pyroute2 backend if available, falls back to conntrack subprocess.
    """

    def __init__(
        self,
        callback: Callable[[Connection], None],
        include_lan: bool = False,
    ) -> None:
        _check_permissions()

        self._resolver = ProcResolver()
        self._include_lan = include_lan

        # Auto-select backend
        if _try_import_pyroute2():
            self._backend = _Pyroute2Backend(callback, self._resolver, include_lan)
            self._backend_name = "pyroute2/netlink"
        elif shutil.which("conntrack") is not None:
            self._backend = _SubprocessBackend(callback, self._resolver, include_lan)
            self._backend_name = "conntrack-subprocess"
        else:
            raise RuntimeError(
                "No conntrack backend available.\n"
                "Install pyroute2 (pip install pyroute2) OR conntrack-tools (apt/dnf install conntrack-tools)."
            )

    @property
    def backend_name(self) -> str:
        return self._backend_name

    async def start(self) -> None:
        await self._backend.start()

    async def stop(self) -> None:
        await self._backend.stop()
