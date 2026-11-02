"""Lead Record & CSV Export Module.

Defines the Lead dataclass and serializes dormant IPv4 seller leads into standard CSV format.
"""

import csv
import io
import logging
from dataclasses import asdict, dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)

DEFAULT_PRICE_PER_IP = 20.28


@dataclass
class IPv4Lead:
    prefix: str
    size: str
    ips: int
    RIR: str
    org: str
    est_value_usd: float
    liveness_flags: str
    dormant_score: float
    priority: str
    alloc_date: str
    country: str
    contact_domain: str
    contact_emails: str
    opaque_id: str


def format_liveness_flags(
    unannounced: bool,
    domain_resolves: bool,
    mx_alive: bool,
    is_legacy: bool,
    ris_peers: int = 0,
) -> str:
    """Format liveness flags as a clean semicolon-delimited string."""
    flags = [
        f"unannounced={unannounced}",
        f"domain_resolves={domain_resolves}",
        f"mx_alive={mx_alive}",
        f"is_legacy={is_legacy}",
    ]
    if ris_peers > 0:
        flags.append(f"ris_peers={ris_peers}")
    return ";".join(flags)


def export_leads_to_csv(leads: List[IPv4Lead], output_path_or_stream) -> None:
    """Write list of IPv4Lead records to CSV."""
    fieldnames = [
        "prefix",
        "size",
        "ips",
        "RIR",
        "org",
        "est_value_usd",
        "liveness_flags",
        "dormant_score",
        "priority",
        "alloc_date",
        "country",
        "contact_domain",
        "contact_emails",
        "opaque_id",
    ]

    # Sort leads descending by dormant_score, then by est_value_usd
    sorted_leads = sorted(
        leads,
        key=lambda l: (l.dormant_score, l.est_value_usd),
        reverse=True
    )

    if isinstance(output_path_or_stream, str):
        with open(output_path_or_stream, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for lead in sorted_leads:
                writer.writerow(asdict(lead))
        logger.info("Exported %d leads to %s", len(leads), output_path_or_stream)
    else:
        writer = csv.DictWriter(output_path_or_stream, fieldnames=fieldnames)
        writer.writeheader()
        for lead in sorted_leads:
            writer.writerow(asdict(lead))
