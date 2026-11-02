"""Unit tests for Dormant-IPv4 Seller Lead Detector.

Tests RIR parsing, legacy detection, BGP MRT parsing, Radix Trie lookups,
liveness scoring, CSV export, and fixture-based offline pipeline execution.
"""

import csv
import io
import ipaddress
import os
import unittest
from unittest.mock import MagicMock, patch

from bgp import BGPTable, load_bview_mrt, parse_mrt_stream
from leads import IPv4Lead, export_leads_to_csv, format_liveness_flags
from liveness import (
    check_domain_liveness,
    extract_domain_from_email,
    guess_domain_from_org,
    score_dormant_likelihood,
)
from rir import (
    RIRAllocation,
    is_legacy_date,
    parse_rir_file,
    parse_rir_line,
)
from detector import build_leads_for_candidates

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_ARIN_PATH = os.path.join(FIXTURES_DIR, "sample_arin_extended.txt")
SAMPLE_RIPE_PATH = os.path.join(FIXTURES_DIR, "sample_ripe_extended.txt")
SAMPLE_BVIEW_MRT = os.path.join(FIXTURES_DIR, "sample_bview.mrt")
SAMPLE_BVIEW_GZ = os.path.join(FIXTURES_DIR, "sample_bview.mrt.gz")


class TestRIRParser(unittest.TestCase):
    """Tests for ARIN and RIPE extended delegation parsing."""

    def test_legacy_date_cutoff(self):
        # Established cutoff is 19971222
        self.assertTrue(is_legacy_date("19940418"))
        self.assertTrue(is_legacy_date("19830119"))
        self.assertTrue(is_legacy_date("00000000"))
        self.assertTrue(is_legacy_date(""))
        self.assertFalse(is_legacy_date("19980101"))
        self.assertFalse(is_legacy_date("20250113"))

    def test_parse_arin_extended(self):
        allocs = parse_rir_file(SAMPLE_ARIN_PATH, min_ips=1024)
        prefixes = [a.prefix for a in allocs]
        
        # 170.119.0.0/16 (/16 = 65536 IPs, legacy)
        self.assertIn("170.119.0.0/16", prefixes)
        lead_170 = next(a for a in allocs if a.prefix == "170.119.0.0/16")
        self.assertEqual(lead_170.ips, 65536)
        self.assertEqual(lead_170.size, "/16")
        self.assertEqual(lead_170.rir, "ARIN")
        self.assertTrue(lead_170.is_legacy)
        self.assertEqual(lead_170.opaque_id, "3e2585b7718f3bac5202561d525cead8")

        # 198.51.100.0/22 (/22 = 1024 IPs, legacy)
        self.assertIn("198.51.100.0/22", prefixes)
        lead_198 = next(a for a in allocs if a.prefix == "198.51.100.0/22")
        self.assertEqual(lead_198.ips, 1024)
        self.assertTrue(lead_198.is_legacy)

        # 1.178.16.0/20 (4096 IPs, modern)
        self.assertIn("1.178.16.0/20", prefixes)
        lead_1 = next(a for a in allocs if a.prefix == "1.178.16.0/20")
        self.assertFalse(lead_1.is_legacy)

        # Small block 1.178.81.0 (/24 = 256 IPs) filtered out
        self.assertNotIn("1.178.81.0/24", prefixes)
        
        # Reserved 10.0.0.0/8 filtered out
        self.assertNotIn("10.0.0.0/8", prefixes)

    def test_parse_ripe_extended(self):
        allocs = parse_rir_file(SAMPLE_RIPE_PATH, min_ips=1024)
        prefixes = [a.prefix for a in allocs]

        # 193.0.0.0/16 (legacy)
        self.assertIn("193.0.0.0/16", prefixes)
        lead_193 = next(a for a in allocs if a.prefix == "193.0.0.0/16")
        self.assertEqual(lead_193.rir, "RIPE")
        self.assertTrue(lead_193.is_legacy)
        self.assertEqual(lead_193.ips, 65536)

        # 194.109.0.0/21 (legacy assigned)
        self.assertIn("194.109.0.0/21", prefixes)
        lead_194 = next(a for a in allocs if a.prefix == "194.109.0.0/21")
        self.assertEqual(lead_194.status, "assigned")
        self.assertTrue(lead_194.is_legacy)
        self.assertEqual(lead_194.ips, 2048)

        # 2.4.0.0/14 (262144 IPs)
        self.assertIn("2.4.0.0/14", prefixes)


class TestBGPTable(unittest.TestCase):
    """Tests for BGP Radix Trie and MRT Parser."""

    def test_radix_trie_prefix_matching(self):
        table = BGPTable()
        table.insert_str("8.8.8.0/24")
        table.insert_str("1.178.16.0/20")

        # Exact announced match
        self.assertTrue(table.is_announced(ipaddress.IPv4Network("8.8.8.0/24")))
        # Covering block contains announced sub-prefix -> True (not dark)
        self.assertTrue(table.is_announced(ipaddress.IPv4Network("8.8.0.0/16")))
        self.assertTrue(table.is_announced(ipaddress.IPv4Network("1.178.16.0/20")))
        # Sub-prefix inside announced covering route -> True
        self.assertTrue(table.is_announced(ipaddress.IPv4Network("1.178.16.0/24")))

        # Completely unannounced dark prefix -> False
        self.assertFalse(table.is_announced(ipaddress.IPv4Network("170.119.0.0/16")))
        self.assertFalse(table.is_announced(ipaddress.IPv4Network("193.0.0.0/16")))

    def test_load_bview_mrt_fixture(self):
        table_raw = load_bview_mrt(SAMPLE_BVIEW_MRT)
        self.assertGreaterEqual(table_raw.total_prefixes, 2)
        self.assertTrue(table_raw.is_announced(ipaddress.IPv4Network("1.178.16.0/20")))
        self.assertTrue(table_raw.is_announced(ipaddress.IPv4Network("2.4.0.0/14")))
        self.assertFalse(table_raw.is_announced(ipaddress.IPv4Network("170.119.0.0/16")))

        # Test gzip decompression support
        table_gz = load_bview_mrt(SAMPLE_BVIEW_GZ)
        self.assertTrue(table_gz.is_announced(ipaddress.IPv4Network("1.178.16.0/20")))
        self.assertFalse(table_gz.is_announced(ipaddress.IPv4Network("170.119.0.0/16")))


class TestLivenessAndScoring(unittest.TestCase):
    """Tests for liveness utilities and scoring model."""

    def test_domain_extraction(self):
        self.assertEqual(extract_domain_from_email("admin@pplweb.com"), "pplweb.com")
        self.assertEqual(extract_domain_from_email("john.doe@sub.company.org"), "sub.company.org")
        self.assertIsNone(extract_domain_from_email("invalid-email"))

    def test_guess_domain_from_org(self):
        self.assertEqual(guess_domain_from_org("Acme Corporation"), "acme.com")
        self.assertEqual(guess_domain_from_org("Global Logistics LLC"), "globallogistics.com")

    def test_dormant_likelihood_scoring(self):
        # Prime Target: Unannounced + Legacy + Resolving Domain + Active MX + /16
        score, priority, breakdown = score_dormant_likelihood(
            unannounced=True,
            is_legacy=True,
            alloc_date="19940418",
            domain_resolves=True,
            mx_alive=True,
            ips=65536,
        )
        self.assertGreaterEqual(score, 85.0)
        self.assertEqual(priority, "PRIME_TARGET")
        self.assertEqual(breakdown["unannounced_dark_bgp"], 35.0)
        self.assertEqual(breakdown["legacy_status"], 25.0)

        # Announced Block: Not unannounced -> low score
        low_score, low_priority, _ = score_dormant_likelihood(
            unannounced=False,
            is_legacy=False,
            alloc_date="20220101",
            domain_resolves=True,
            mx_alive=True,
            ips=1024,
        )
        self.assertLess(low_score, 40.0)
        self.assertEqual(low_priority, "LOW")


class TestLeadExport(unittest.TestCase):
    """Tests for CSV serialization and valuation math."""

    def test_csv_export(self):
        lead = IPv4Lead(
            prefix="170.119.0.0/16",
            size="/16",
            ips=65536,
            RIR="ARIN",
            org="LG&E Energy",
            est_value_usd=round(65536 * 20.28, 2),
            liveness_flags="unannounced=True;domain_resolves=True;mx_alive=True;is_legacy=True",
            dormant_score=95.0,
            priority="PRIME_TARGET",
            alloc_date="19940418",
            country="US",
            contact_domain="pplweb.com",
            contact_emails="admin@pplweb.com",
            opaque_id="3e2585b7718f3bac5202561d525cead8",
        )

        stream = io.StringIO()
        export_leads_to_csv([lead], stream)
        stream.seek(0)
        
        reader = csv.DictReader(stream)
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["prefix"], "170.119.0.0/16")
        self.assertEqual(rows[0]["est_value_usd"], "1329070.08")
        self.assertEqual(rows[0]["priority"], "PRIME_TARGET")
        self.assertEqual(rows[0]["org"], "LG&E Energy")


class TestEndToEndPipeline(unittest.TestCase):
    """End-to-end integration test with fixtures and zero network calls."""

    def test_pipeline_with_fixtures(self):
        # 1. Load candidate allocations from fixture files
        arin_allocs = parse_rir_file(SAMPLE_ARIN_PATH, min_ips=1024)
        ripe_allocs = parse_rir_file(SAMPLE_RIPE_PATH, min_ips=1024)
        all_allocs = arin_allocs + ripe_allocs

        # 2. Load BGP table from fixture MRT
        bgp_table = load_bview_mrt(SAMPLE_BVIEW_MRT)

        # 3. Run lead builder (skip_dns=True for offline reproducibility)
        leads = build_leads_for_candidates(
            candidates=all_allocs,
            bgp_table=bgp_table,
            price_per_ip=20.28,
            skip_dns=True,
            unannounced_only=True,
        )

        emitted_prefixes = [l.prefix for l in leads]
        
        # Verify that unannounced dark blocks are emitted
        self.assertIn("170.119.0.0/16", emitted_prefixes)
        self.assertIn("198.51.100.0/22", emitted_prefixes)
        self.assertIn("193.0.0.0/16", emitted_prefixes)
        self.assertIn("194.109.0.0/21", emitted_prefixes)

        # Verify that announced blocks are filtered out
        self.assertNotIn("1.178.16.0/20", emitted_prefixes)
        self.assertNotIn("2.4.0.0/14", emitted_prefixes)

        # Verify valuation for 170.119.0.0/16 (65536 * 20.28)
        lead_170 = next(l for l in leads if l.prefix == "170.119.0.0/16")
        self.assertEqual(lead_170.est_value_usd, 1329070.08)
        self.assertEqual(lead_170.RIR, "ARIN")


if __name__ == "__main__":
    unittest.main()
