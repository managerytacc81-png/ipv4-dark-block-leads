"""RIR Extended Delegation Module.

Handles downloading, caching, and parsing ARIN and RIPE extended delegation statistics.
Extracts allocated/assigned IPv4 prefixes >= /22 (>= 1,024 IPs), flags legacy records,
and captures the opaque org identifier from the extended delegation format.
"""

import ipaddress
import logging
import math
import os
import urllib.request
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

ARIN_EXTENDED_URL = "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"
RIPE_EXTENDED_URL = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"

# ARIN establishment cutoff date for legacy allocations (December 22, 1997)
LEGACY_CUTOFF_DATE = 19971222


@dataclass
class RIRAllocation:
    """Represents an IPv4 allocation or assignment from an RIR extended delegation file."""
    prefix: str                 # e.g. '170.119.0.0/16'
    network: ipaddress.IPv4Network
    size: str                   # e.g. '/16'
    ips: int                    # e.g. 65536
    rir: str                    # 'ARIN', 'RIPE', etc.
    country: str                # 'US', 'DE', etc.
    alloc_date: str             # '19940418' or '00000000'
    status: str                 # 'allocated' or 'assigned'
    opaque_id: str              # Opaque ID / org identifier from 8th column
    is_legacy: bool             # True if allocated prior to RIR policies (pre-19971222)


def is_legacy_date(date_str: str) -> bool:
    """Determine whether an allocation date corresponds to legacy IPv4 space.
    
    Legacy space comprises blocks allocated prior to RIR establishment (pre-19971222)
    or recorded with date '00000000'.
    """
    if not date_str:
        return True
    date_clean = date_str.strip()
    if date_clean == "00000000":
        return True
    if date_clean.isdigit():
        try:
            val = int(date_clean)
            return val < LEGACY_CUTOFF_DATE
        except ValueError:
            return False
    return False


def parse_rir_line(line: str, min_ips: int = 1024) -> List[RIRAllocation]:
    """Parse a single line from an RIR extended delegation file.
    
    Format:
      registry|cc|type|start|value|date|status[|opaque-id]
    
    Returns a list of RIRAllocation objects matching criteria (IPv4, allocated/assigned, >= min_ips).
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    
    parts = line.split("|")
    if len(parts) < 7:
        return []
    
    registry = parts[0].strip().upper()
    if registry == "RIPENCC":
        registry = "RIPE"
        
    country = parts[1].strip()
    rec_type = parts[2].strip().lower()
    start_ip_str = parts[3].strip()
    value_str = parts[4].strip()
    date_str = parts[5].strip()
    status = parts[6].strip().lower()
    opaque_id = parts[7].strip() if len(parts) >= 8 else ""

    # Filter for IPv4 records
    if rec_type != "ipv4":
        return []
    
    # Ignore summary records (*|ipv4|*|...)
    if country == "*" or start_ip_str == "*":
        return []

    # Must be assigned or allocated
    if status not in ("allocated", "assigned"):
        return []

    try:
        count = int(value_str)
    except ValueError:
        return []

    if count < min_ips:
        return []

    try:
        start_ip = ipaddress.IPv4Address(start_ip_str)
        end_ip = start_ip + count - 1
        networks = list(ipaddress.summarize_address_range(start_ip, end_ip))
    except (ValueError, ipaddress.AddressValueError):
        logger.debug("Failed to parse IP range %s count %s", start_ip_str, value_str)
        return []

    legacy = is_legacy_date(date_str)
    allocations = []
    for net in networks:
        if net.num_addresses >= min_ips:
            allocations.append(RIRAllocation(
                prefix=str(net),
                network=net,
                size=f"/{net.prefixlen}",
                ips=net.num_addresses,
                rir=registry,
                country=country,
                alloc_date=date_str,
                status=status,
                opaque_id=opaque_id,
                is_legacy=legacy,
            ))
            
    return allocations


def parse_rir_file(file_path_or_stream, min_ips: int = 1024) -> List[RIRAllocation]:
    """Parse an open file stream or path containing RIR extended delegation stats."""
    allocations: List[RIRAllocation] = []
    
    if isinstance(file_path_or_stream, str):
        with open(file_path_or_stream, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                allocations.extend(parse_rir_line(line, min_ips=min_ips))
    else:
        for line in file_path_or_stream:
            if isinstance(line, bytes):
                line = line.decode("utf-8", errors="ignore")
            allocations.extend(parse_rir_line(line, min_ips=min_ips))
            
    return allocations


def download_file(url: str, dest_path: str, force: bool = False, timeout: int = 60) -> str:
    """Download a file with HTTP User-Agent and atomic write to destination path."""
    if os.path.exists(dest_path) and not force and os.path.getsize(dest_path) > 0:
        logger.info("Using cached file: %s (%d bytes)", dest_path, os.path.getsize(dest_path))
        return dest_path

    os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
    temp_path = f"{dest_path}.tmp"
    logger.info("Downloading %s -> %s", url, dest_path)
    
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Dormant-IPv4-Detector/1.0 (+https://github.com/revenue-eval)"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as response, open(temp_path, "wb") as out_file:
        chunk_size = 65536
        while True:
            chunk = response.read(chunk_size)
            if not chunk:
                break
            out_file.write(chunk)
            
    os.replace(temp_path, dest_path)
    logger.info("Downloaded %s (%d bytes)", dest_path, os.path.getsize(dest_path))
    return dest_path


def load_rir_delegations(
    data_dir: str,
    min_ips: int = 1024,
    force_download: bool = False,
    include_arin: bool = True,
    include_ripe: bool = True,
    arin_custom_path: Optional[str] = None,
    ripe_custom_path: Optional[str] = None,
) -> List[RIRAllocation]:
    """Load allocations from ARIN and RIPE extended delegation files."""
    os.makedirs(data_dir, exist_ok=True)
    all_allocs: List[RIRAllocation] = []

    if include_arin:
        arin_path = arin_custom_path or os.path.join(data_dir, "delegated-arin-extended-latest.txt")
        if not arin_custom_path or not os.path.exists(arin_custom_path):
            download_file(ARIN_EXTENDED_URL, arin_path, force=force_download)
        logger.info("Parsing ARIN extended delegations from %s...", arin_path)
        arin_allocs = parse_rir_file(arin_path, min_ips=min_ips)
        logger.info("Found %d ARIN IPv4 candidate allocations >= /%d", len(arin_allocs), 32 - int(math.log2(min_ips)))
        all_allocs.extend(arin_allocs)

    if include_ripe:
        ripe_path = ripe_custom_path or os.path.join(data_dir, "delegated-ripencc-extended-latest.txt")
        if not ripe_custom_path or not os.path.exists(ripe_custom_path):
            download_file(RIPE_EXTENDED_URL, ripe_path, force=force_download)
        logger.info("Parsing RIPE extended delegations from %s...", ripe_path)
        ripe_allocs = parse_rir_file(ripe_path, min_ips=min_ips)
        logger.info("Found %d RIPE IPv4 candidate allocations >= /%d", len(ripe_allocs), 32 - int(math.log2(min_ips)))
        all_allocs.extend(ripe_allocs)

    return all_allocs
