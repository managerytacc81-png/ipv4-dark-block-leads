"""BGP Routing Table & Unannounced Detection Module.

Supports:
1. Pure Python parser for RFC 6396 MRT TABLE_DUMP_V2 dumps (e.g. RIPE RIS rrc00 latest-bview.gz).
2. Bitwise Radix Trie for O(prefixlen) lookup to check if a prefix or any sub-prefix is announced.
3. RIPEstat API fallback (routing-status and prefix-overview) for fast per-prefix sampling.
"""

import gzip
import io
import ipaddress
import json
import logging
import os
import socket
import struct
import urllib.request
from typing import Dict, Iterator, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

BVIEW_RRC00_URL = "https://data.ris.ripe.net/rrc00/latest-bview.gz"
RIPESTAT_ROUTING_STATUS_URL = "https://stat.ripe.net/data/routing-status/data.json?resource="
RIPESTAT_PREFIX_OVERVIEW_URL = "https://stat.ripe.net/data/prefix-overview/data.json?resource="


class RadixTrieNode:
    """Node in binary prefix trie."""
    __slots__ = ("children", "is_prefix")
    
    def __init__(self):
        self.children = [None, None]
        self.is_prefix = False


class BGPTable:
    """Holds BGP announced IPv4 routing state using a binary prefix trie."""

    def __init__(self):
        self.root = RadixTrieNode()
        self.total_prefixes = 0

    def insert(self, network: ipaddress.IPv4Network) -> None:
        """Insert an announced IPv4 network into the routing trie."""
        net_int = int(network.network_address)
        prefixlen = network.prefixlen
        node = self.root
        for i in range(31, 31 - prefixlen, -1):
            bit = (net_int >> i) & 1
            if node.children[bit] is None:
                node.children[bit] = RadixTrieNode()
            node = node.children[bit]
        if not node.is_prefix:
            node.is_prefix = True
            self.total_prefixes += 1

    def insert_str(self, prefix_str: str) -> None:
        """Parse string prefix and insert."""
        try:
            net = ipaddress.IPv4Network(prefix_str, strict=False)
            self.insert(net)
        except (ValueError, ipaddress.AddressValueError):
            pass

    def _has_any_subprefix(self, node: RadixTrieNode) -> bool:
        """Check if node or any descendant is marked as a prefix."""
        if node.is_prefix:
            return True
        for child in node.children:
            if child and self._has_any_subprefix(child):
                return True
        return False

    def is_announced(self, network: ipaddress.IPv4Network) -> bool:
        """Return True if network is announced, covered by a larger route, or has announced sub-prefixes.
        
        Returns False if the entire block is unannounced (dark block).
        """
        net_int = int(network.network_address)
        prefixlen = network.prefixlen
        node = self.root

        for i in range(31, 31 - prefixlen, -1):
            # If covering prefix is announced (e.g. a /16 covers this /22), it is announced
            # We ignore default route 0.0.0.0/0 to avoid false positives for unannounced space
            if node.is_prefix and i < 31:
                return True
            bit = (net_int >> i) & 1
            if node.children[bit] is None:
                return False
            node = node.children[bit]

        # Check if this exact prefix or any more-specific sub-prefix is announced
        return self._has_any_subprefix(node)


def parse_mrt_stream(stream, max_records: Optional[int] = None) -> Iterator[str]:
    """Parse MRT stream (RFC 6396) TABLE_DUMP_V2 RIB_IPV4_UNICAST records.
    
    Yields prefix strings (e.g. '192.0.2.0/24').
    """
    count = 0
    while True:
        header = stream.read(12)
        if len(header) < 12:
            break

        ts, m_type, m_subtype, length = struct.unpack(">IHHI", header)
        record_data = stream.read(length)
        if len(record_data) < length:
            break

        # TABLE_DUMP_V2 = 13, RIB_IPV4_UNICAST = 2
        if m_type == 13 and m_subtype == 2:
            if len(record_data) >= 5:
                seq, pfx_len = struct.unpack(">IB", record_data[:5])
                pfx_bytes_len = (pfx_len + 7) // 8
                if 5 + pfx_bytes_len <= len(record_data):
                    pfx_bytes = record_data[5:5 + pfx_bytes_len]
                    padded = pfx_bytes + b"\x00" * (4 - len(pfx_bytes))
                    ip = socket.inet_ntoa(padded)
                    count += 1
                    yield f"{ip}/{pfx_len}"
                    if max_records and count >= max_records:
                        break


def load_bview_mrt(file_path: str, max_records: Optional[int] = None) -> BGPTable:
    """Load announced prefixes from an MRT bview file (.mrt or .gz)."""
    table = BGPTable()
    is_gz = file_path.endswith(".gz")
    open_func = gzip.open if is_gz else open

    logger.info("Parsing BGP MRT file %s...", file_path)
    with open_func(file_path, "rb") as f:
        for pfx_str in parse_mrt_stream(f, max_records=max_records):
            table.insert_str(pfx_str)

    logger.info("Loaded %d unique announced prefixes into BGP table", table.total_prefixes)
    return table


def check_ripestat_routing_status(prefix: str, timeout: int = 8) -> Dict:
    """Query RIPEstat routing-status API for an IPv4 prefix.
    
    Returns a dict with:
      announced: bool (True if announced by at least 1 peer or has origins)
      ris_peers_seeing: int
      origins: List[str]
      last_seen: Optional[str]
    """
    url = f"{RIPESTAT_ROUTING_STATUS_URL}{prefix}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Dormant-IPv4-Detector/1.0 (+https://github.com/revenue-eval)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8")).get("data", {})
            vis = data.get("visibility", {}).get("v4", {})
            peers_seeing = vis.get("ris_peers_seeing", 0)
            origins = [str(o.get("origin")) for o in data.get("origins", []) if o.get("origin")]
            last_seen_info = data.get("last_seen", {})
            last_seen_time = last_seen_info.get("time") if last_seen_info else None
            
            announced = (peers_seeing > 0) or (len(origins) > 0)
            return {
                "announced": announced,
                "ris_peers_seeing": peers_seeing,
                "origins": origins,
                "last_seen": last_seen_time,
                "error": None,
            }
    except Exception as e:
        logger.debug("RIPEstat routing-status error for %s: %s", prefix, e)
        return {
            "announced": False,
            "ris_peers_seeing": 0,
            "origins": [],
            "last_seen": None,
            "error": str(e),
        }


def check_ripestat_prefix_overview(prefix: str, timeout: int = 8) -> Dict:
    """Query RIPEstat prefix-overview API for an IPv4 prefix.
    
    Returns a dict with:
      announced: bool
      asns: List[int]
    """
    url = f"{RIPESTAT_PREFIX_OVERVIEW_URL}{prefix}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Dormant-IPv4-Detector/1.0 (+https://github.com/revenue-eval)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8")).get("data", {})
            announced = bool(data.get("announced", False))
            asns = [a.get("asn") for a in data.get("asns", []) if a.get("asn")]
            return {
                "announced": announced,
                "asns": asns,
                "error": None,
            }
    except Exception as e:
        logger.debug("RIPEstat prefix-overview error for %s: %s", prefix, e)
        return {
            "announced": False,
            "asns": [],
            "error": str(e),
        }
