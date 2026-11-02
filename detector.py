#!/usr/bin/env python3
"""Dormant-IPv4 Seller Lead Detector.

Identifies unannounced / dark IPv4 address blocks held by legacy organizations,
performs DNS/WHOIS liveness verification on holding entities, calculates estimated
market valuation, and generates high-value broker leads.
"""

import argparse
import logging
import os
import sys
from typing import List, Optional

from bgp import (
    BGPTable,
    BVIEW_RRC00_URL,
    check_ripestat_routing_status,
    load_bview_mrt,
)
from leads import (
    DEFAULT_PRICE_PER_IP,
    IPv4Lead,
    export_leads_to_csv,
    format_liveness_flags,
)
from liveness import (
    check_domain_liveness,
    extract_domain_from_email,
    guess_domain_from_org,
    lookup_org_and_contacts,
    score_dormant_likelihood,
)
from rir import (
    ARIN_EXTENDED_URL,
    RIRAllocation,
    RIPE_EXTENDED_URL,
    download_file,
    load_rir_delegations,
    parse_rir_file,
)

logger = logging.getLogger("ipv4_detector")


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def build_leads_for_candidates(
    candidates: List[RIRAllocation],
    bgp_table: Optional[BGPTable] = None,
    price_per_ip: float = DEFAULT_PRICE_PER_IP,
    skip_dns: bool = False,
    sample_limit: Optional[int] = None,
    unannounced_only: bool = True,
) -> List[IPv4Lead]:
    """Process candidate allocations and produce scored IPv4Lead records."""
    leads: List[IPv4Lead] = []
    
    target_candidates = candidates[:sample_limit] if sample_limit else candidates
    logger.info("Evaluating %d candidate IPv4 blocks...", len(target_candidates))

    for idx, alloc in enumerate(target_candidates, 1):
        prefix_str = alloc.prefix
        logger.debug("[%d/%d] Checking %s (%s, %d IPs, legacy=%s)...",
                     idx, len(target_candidates), prefix_str, alloc.rir, alloc.ips, alloc.is_legacy)

        # 1. Determine announced / unannounced status
        unannounced = False
        ris_peers = 0
        if bgp_table is not None:
            # Check against local MRT BGP table trie
            is_announced = bgp_table.is_announced(alloc.network)
            unannounced = not is_announced
        else:
            # Query RIPEstat routing-status API
            stat = check_ripestat_routing_status(prefix_str)
            ris_peers = stat.get("ris_peers_seeing", 0)
            unannounced = not stat.get("announced", False)

        # Filter out announced blocks if unannounced_only is active
        if unannounced_only and not unannounced:
            logger.debug("Skipping %s: currently announced in BGP (ris_peers=%d)", prefix_str, ris_peers)
            continue

        # 2. Organization and contact resolution
        org_name = ""
        emails: List[str] = []
        domain = None

        if not skip_dns:
            org_info = lookup_org_and_contacts(
                ip_or_prefix=prefix_str,
                rir=alloc.rir,
                opaque_id=alloc.opaque_id,
            )
            org_name = org_info.get("org", "")
            emails = org_info.get("emails", [])

            # Extract or guess domain
            for email in emails:
                d = extract_domain_from_email(email)
                if d:
                    domain = d
                    break
            if not domain and org_name:
                domain = guess_domain_from_org(org_name)
        else:
            org_name = f"ORG-{alloc.opaque_id[:8]}" if alloc.opaque_id else "Unassigned Holder"

        # 3. DNS and MX liveness checks
        domain_resolves = False
        mx_alive = False
        if not skip_dns and domain:
            domain_resolves, mx_alive = check_domain_liveness(domain)

        # 4. Score dormant likelihood
        score, priority, breakdown = score_dormant_likelihood(
            unannounced=unannounced,
            is_legacy=alloc.is_legacy,
            alloc_date=alloc.alloc_date,
            domain_resolves=domain_resolves,
            mx_alive=mx_alive,
            ips=alloc.ips,
        )

        # 5. Valuation
        est_value = round(alloc.ips * price_per_ip, 2)

        # 6. Liveness flags formatting
        flags_str = format_liveness_flags(
            unannounced=unannounced,
            domain_resolves=domain_resolves,
            mx_alive=mx_alive,
            is_legacy=alloc.is_legacy,
            ris_peers=ris_peers,
        )

        lead = IPv4Lead(
            prefix=prefix_str,
            size=alloc.size,
            ips=alloc.ips,
            RIR=alloc.rir,
            org=org_name or f"Entity-{alloc.opaque_id[:8]}",
            est_value_usd=est_value,
            liveness_flags=flags_str,
            dormant_score=score,
            priority=priority,
            alloc_date=alloc.alloc_date,
            country=alloc.country,
            contact_domain=domain or "",
            contact_emails=";".join(emails) if emails else "",
            opaque_id=alloc.opaque_id,
        )
        leads.append(lead)
        logger.info(
            "LEAD FOUND: %s (%s, %d IPs) | Holder: %s | Est: $%s | Score: %.1f (%s) | Unannounced: %s",
            lead.prefix, lead.size, lead.ips, lead.org, f"{lead.est_value_usd:,.2f}", lead.dormant_score, lead.priority, unannounced
        )

    return leads


def parse_args():
    parser = argparse.ArgumentParser(
        description="Dormant-IPv4 Seller Lead Detector (ARIN/RIPE + BGP + Liveness + Valuation)"
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=None,
        metavar="N",
        help="Run in sample mode: evaluate only N candidate prefixes via RIPEstat API to control CI/runtime",
    )
    parser.add_argument(
        "--price-per-ip",
        type=float,
        default=DEFAULT_PRICE_PER_IP,
        help=f"Valuation rate per IPv4 address in USD (default: ${DEFAULT_PRICE_PER_IP} per Q3 2026 market)",
    )
    parser.add_argument(
        "--min-ips",
        type=int,
        default=1024,
        help="Minimum block size in IPs (default: 1024, which is a /22)",
    )
    parser.add_argument(
        "--max-ips",
        type=int,
        default=None,
        help="Maximum block size in IPs (e.g. 65536 to focus on commercial /16 to /22 blocks)",
    )
    parser.add_argument(
        "--prefix-size",
        type=str,
        default=None,
        help="Filter for specific CIDR prefix size, e.g. '/16', '/20', '/22'",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="dormant_ipv4_leads.csv",
        help="Output CSV file path (default: dormant_ipv4_leads.csv)",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data",
        help="Directory to cache RIR and BGP files (default: data/)",
    )
    parser.add_argument(
        "--arin-file",
        type=str,
        default=None,
        help="Path to local ARIN extended delegation file (skips ARIN download)",
    )
    parser.add_argument(
        "--ripe-file",
        type=str,
        default=None,
        help="Path to local RIPE extended delegation file (skips RIPE download)",
    )
    parser.add_argument(
        "--bgp-file",
        type=str,
        default=None,
        help="Path to local BGP table MRT file (.mrt or .gz)",
    )
    parser.add_argument(
        "--download-bgp",
        action="store_true",
        help="Download latest full BGP table view from RIPE RIS (latest-bview.gz)",
    )
    parser.add_argument(
        "--legacy-only",
        action="store_true",
        help="Filter exclusively for legacy allocations (pre-19971222)",
    )
    parser.add_argument(
        "--include-announced",
        action="store_true",
        help="Include announced prefixes in output (by default only unannounced dark blocks are emitted)",
    )
    parser.add_argument(
        "--skip-dns",
        action="store_true",
        help="Skip online DNS/MX queries (useful in offline or fixture test environments)",
    )
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Force re-download of RIR delegation files even if cached",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable detailed debug logging",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(args.verbose)

    logger.info("=== Dormant-IPv4 Seller Lead Detector Starting ===")
    logger.info("Settings: min_ips=%d (>= /%d), price_per_ip=$%.2f, sample=%s",
                args.min_ips, 32 - int(args.min_ips.bit_length() - 1), args.price_per_ip, args.sample)

    # 1. Load RIR extended delegations
    allocations = load_rir_delegations(
        data_dir=args.data_dir,
        min_ips=args.min_ips,
        force_download=args.force_download,
        arin_custom_path=args.arin_file,
        ripe_custom_path=args.ripe_file,
    )
    logger.info("Loaded %d total IPv4 allocations >= %d IPs from RIR files", len(allocations), args.min_ips)

    # 2. Filtering
    candidates = allocations
    if args.prefix_size:
        req_size = args.prefix_size if args.prefix_size.startswith("/") else f"/{args.prefix_size}"
        candidates = [a for a in candidates if a.size == req_size]
        logger.info("Filtered for prefix size %s: %d candidates", req_size, len(candidates))

    if args.max_ips:
        candidates = [a for a in candidates if a.ips <= args.max_ips]
        logger.info("Filtered for max_ips <= %d: %d candidates", args.max_ips, len(candidates))

    if args.legacy_only:
        candidates = [a for a in candidates if a.is_legacy]
        logger.info("Filtered to %d legacy-holder records (pre-19971222)", len(candidates))
    else:
        # Sort candidates: legacy first, then descending by IP block size
        candidates = sorted(candidates, key=lambda a: (a.is_legacy, a.ips), reverse=True)

    # 3. Handle BGP Routing Table
    bgp_table: Optional[BGPTable] = None
    if args.bgp_file:
        bgp_table = load_bview_mrt(args.bgp_file)
    elif args.download_bgp:
        bgp_dest = os.path.join(args.data_dir, "latest-bview.gz")
        download_file(BVIEW_RRC00_URL, bgp_dest, force=args.force_download)
        bgp_table = load_bview_mrt(bgp_dest)

    # 4. Execute Lead Extraction
    sample_size = args.sample
    if sample_size is None and bgp_table is None:
        logger.warning(
            "Neither --bgp-file nor --download-bgp provided. "
            "Defaulting to --sample 25 via RIPEstat API to keep runtime fast."
        )
        sample_size = 25

    leads = build_leads_for_candidates(
        candidates=candidates,
        bgp_table=bgp_table,
        price_per_ip=args.price_per_ip,
        skip_dns=args.skip_dns,
        sample_limit=sample_size,
        unannounced_only=not args.include_announced,
    )

    # 5. Export to CSV
    export_leads_to_csv(leads, args.output)

    # 6. Summary metrics
    total_ips = sum(l.ips for l in leads)
    total_val = sum(l.est_value_usd for l in leads)
    prime_count = sum(1 for l in leads if l.priority == "PRIME_TARGET")
    logger.info("==================================================")
    logger.info("Detection Completed: %d leads generated", len(leads))
    logger.info("Total Unannounced IPs: %s", f"{total_ips:,}")
    logger.info("Total Pipeline Value: $%s (at $%.2f/IP)", f"{total_val:,.2f}", args.price_per_ip)
    logger.info("Prime Acquisition Targets: %d", prime_count)
    logger.info("Output CSV: %s", os.path.abspath(args.output))
    logger.info("==================================================")


if __name__ == "__main__":
    main()
