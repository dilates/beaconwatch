"""Connection dataclass and normalization utilities."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime


# RFC 1918 + link-local + loopback + multicast
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
]

_LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


@dataclass
class Connection:
    timestamp: datetime
    proto: str                   # "tcp" | "udp"
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    pid: int | None
    process_name: str | None
    process_path: str | None     # full /proc/<pid>/exe path
    bytes_sent: int | None       # from conntrack counters if available
    bytes_recv: int | None
    state: str                   # "new" | "established" | "closed"

    def is_loopback(self) -> bool:
        """Return True if the destination is a loopback address."""
        try:
            addr = ipaddress.ip_address(self.dst_ip)
            return any(addr in net for net in _LOOPBACK_NETWORKS)
        except ValueError:
            return False

    def is_private_dest(self) -> bool:
        """Return True if the destination is in a private/RFC1918 range."""
        try:
            addr = ipaddress.ip_address(self.dst_ip)
            return any(addr in net for net in _PRIVATE_NETWORKS)
        except ValueError:
            return False

    def is_outbound_public(self) -> bool:
        """Return True for connections to public internet destinations."""
        return not self.is_loopback() and not self.is_private_dest()

    def flow_key(self) -> tuple[str | None, str, int, str]:
        """Key for grouping into flows: (process_path_or_name, dst_ip, dst_port, proto)."""
        identity = self.process_path or self.process_name
        return (identity, self.dst_ip, self.dst_port, self.proto)
