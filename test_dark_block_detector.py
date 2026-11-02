"""
Unit tests for Dormant IPv4 Secondary Market Sourcing & Dark-Block Detector
"""

import os
import json
import csv
import unittest
from dark_block_detector import (
    IPv4Allocation,
    ScoredDarkBlockLead,
    DarkBlockScorer,
    DarkBlockExporter,
    CURATED_ALLOCATIONS,
    PREFIX_PRICE_MULTIPLIERS,
    CURRENT_AVG_PRICE_PER_IP
)

class TestDarkBlockScorer(unittest.TestCase):
    def test_calculate_valuation_slash_24(self):
        val = DarkBlockScorer.calculate_valuation(24, 256)
        expected_unit = round(CURRENT_AVG_PRICE_PER_IP * PREFIX_PRICE_MULTIPLIERS["/24"], 2)
        expected_total = round(256 * expected_unit, 2)
        expected_broker = round(expected_total * 0.05, 2)
        expected_referral = round(expected_broker * 0.20, 2)

        self.assertEqual(val["unit_price"], expected_unit)
        self.assertEqual(val["total_value"], expected_total)
        self.assertEqual(val["broker_fee"], expected_broker)
        self.assertEqual(val["referral_fee"], expected_referral)

    def test_evaluate_allocation_confidence_levels(self):
        # 1. Unannounced + Expired domain -> HIGH_CONFIDENCE_DARK
        high_conf = IPv4Allocation(
            registry="arin",
            starting_ip="192.0.2.0",
            count_ips=256,
            prefix_length=24,
            allocation_date="1995-01-01",
            is_legacy=True,
            org_name="Defunct LLC",
            org_handle="DEF-ARIN",
            country="US",
            email_contact=None,
            announced_in_bgp=False,
            domain_status="EXPIRED",
            mx_records_exist=False
        )
        scored_high = DarkBlockScorer.evaluate_allocation(high_conf)
        self.assertEqual(scored_high.dormancy_confidence, "HIGH_CONFIDENCE_DARK")

        # 2. Unannounced + Active industrial company -> PROBABLE_DARK
        prob_conf = IPv4Allocation(
            registry="arin",
            starting_ip="198.51.100.0",
            count_ips=1024,
            prefix_length=22,
            allocation_date="1992-01-01",
            is_legacy=True,
            org_name="Old Steel Foundry",
            org_handle="STEEL-ARIN",
            country="US",
            email_contact=None,
            announced_in_bgp=False,
            domain_status="ACTIVE",
            mx_records_exist=True
        )
        scored_prob = DarkBlockScorer.evaluate_allocation(prob_conf)
        self.assertEqual(scored_prob.dormancy_confidence, "PROBABLE_DARK")

class TestDarkBlockExporter(unittest.TestCase):
    def setUp(self):
        self.test_dir = "/tmp/ipv4_test"
        os.makedirs(self.test_dir, exist_ok=True)
        self.csv_path = os.path.join(self.test_dir, "test_leads.csv")
        self.json_path = os.path.join(self.test_dir, "test_leads.json")

    def tearDown(self):
        for f in [self.csv_path, self.json_path]:
            if os.path.exists(f):
                os.remove(f)

    def test_export_leads_csv_and_json(self):
        leads = [DarkBlockScorer.evaluate_allocation(a) for a in CURATED_ALLOCATIONS]
        DarkBlockExporter.export_leads_csv(leads, self.csv_path)
        DarkBlockExporter.export_leads_json(leads, self.json_path)

        self.assertTrue(os.path.exists(self.csv_path))
        with open(self.csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertEqual(len(rows), len(leads))
            self.assertIn("prefix", reader.fieldnames)
            self.assertIn("estimated_block_value", reader.fieldnames)

        self.assertTrue(os.path.exists(self.json_path))
        with open(self.json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["total_leads"], len(leads))
            self.assertGreater(data["total_pipeline_value_usd"], 0)

    def test_generate_broker_packet(self):
        leads = [DarkBlockScorer.evaluate_allocation(a) for a in CURATED_ALLOCATIONS]
        packet = DarkBlockExporter.generate_broker_packet_markdown(leads)

        self.assertIn("Dormant IPv4 Secondary Market Sourcing & Broker Deal Packet", packet)
        self.assertIn("IPV4 SECONDARY MARKET LEAD INTEL & REFERRAL AGREEMENT", packet)
        self.assertIn("Hilco Streambank", packet)
        self.assertIn("Robert Ketler", packet)

if __name__ == "__main__":
    unittest.main()
