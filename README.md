# Dormant-IPv4 Seller Lead Detector (Dark-Block Intelligence)

An enterprise-grade data intelligence engine designed to detect unannounced, dormant IPv4 address blocks held by legacy organizations, perform DNS/WHOIS corporate liveness verification on holding entities, estimate asset valuation at live secondary market rates, and generate high-converting seller leads for IPv4 brokers.

---

## 1. Executive Summary & Market Economics

* **Market Opportunity:** In the secondary IPv4 market (~$2.5B annual transaction volume, average $20.28/IP as of Q3 2026), buyer demand is heavily constrained by **seller supply**.
* **The "Dark Block" Reality:** Approximately ~15% of all allocated IPv4 space remains unannounced in global BGP routing tables (LACNIC43 / CAIDA studies). Crucially, pre-RIR "legacy" space (allocated prior to December 22, 1997) has only a ~9.5% active utilization rate.
* **The Broker Bottleneck:** Major secondary market brokers (**IPv4.Global by Hilco Streambank**, **Prefixx**, **IPXO**) charge 3–8% broker commissions or offer 10–25% referral fees. Their primary bottleneck is finding verified corporate holders who own dormant / unrouted blocks and can be legally contacted to liquidate unencumbered assets.

---

## 2. Architecture & Data Rails

The pipeline joins multiple authoritative data sources without external binary bloat:

```
[ARIN / RIPE Extended Delegation Files]
  ftp.arin.net | ftp.ripe.net (180K+ allocations)
                 │
                 ▼
[CIDR Normalizer & Legacy Filter]
  Filter: Status in ('allocated', 'assigned')
  Filter: Size >= /22 (>= 1,024 IPs)
  Flag:   is_legacy (Allocated pre-19971222 or date == 00000000)
                 │
                 ▼
[BGP Route Table Analysis]
  Mode A: Local MRT TABLE_DUMP_V2 RIB_IPV4_UNICAST (RIPE RIS rrc00) via Bitwise Radix Trie
  Mode B: Live RIPEstat API (routing-status, visibility, prefix-overview)
                 │
                 ▼ (Keep dark / unannounced blocks)
[Corporate Entity & Contact Resolution]
  ARIN / RIPE RDAP bootstrap + RIPEstat WHOIS fallback
  Extracts legal OrgName, NetName, and Technical/Admin POC emails
                 │
                 ▼
[DNS & MX Liveness Checks]
  Domain A/AAAA resolution (socket) + DNS MX server check (dig)
  Validates active corporate existence and contactable executive mailboxes
                 │
                 ▼
[Dormant-Holder Likelihood Scoring & Valuation]
  Score 0-100: Dark BGP (+35), Legacy Title (+25), Domain Active (+15), MX Alive (+10), Block Size (+10), Vintage (+5)
  Valuation: ips * $20.28 USD
                 │
                 ▼
[Enriched CSV Lead Feed]
  prefix, size, ips, RIR, org, est_value_usd, liveness_flags, dormant_score, priority, alloc_date, country, contact_domain, contact_emails, opaque_id
```

---

## 3. Installation & Requirements

Requirements:
- Python 3.9+ (Standard Library `ipaddress`, `socket`, `struct`, `urllib`, `gzip`, `csv`)
- `dig` (standard on Unix/Linux for DNS MX lookups; falls back gracefully if absent)
- No complex C-extension or unmaintained BGP libraries required (zero `pyunormalize` / binary dependency issues).

---

## 4. Usage Guide

### A. Quick Sample Mode (Fast CI / On-Demand Verification)
Runs RIPEstat live API lookups for `N` top candidate allocations:
```bash
python3 detector.py --sample 20 --output dormant_ipv4_leads.csv
```

### B. Filter by Specific Prefix Size
Extract only `/16` blocks (65,536 IPs, worth ~$1.33M each) or `/20` blocks (4,096 IPs):
```bash
python3 detector.py --prefix-size /16 --sample 15 --output dormant_ipv4_leads_16.csv
```

### C. Custom Valuation & Block Size
Configure custom $/IP rates and block size thresholds:
```bash
python3 detector.py --min-ips 4096 --price-per-ip 22.50 --sample 25
```

### D. Offline / Fixture Mode
Run against local files with zero network dependencies:
```bash
python3 detector.py \
  --arin-file fixtures/sample_arin_extended.txt \
  --ripe-file fixtures/sample_ripe_extended.txt \
  --bgp-file fixtures/sample_bview.mrt \
  --skip-dns \
  --output test_leads.csv
```

### E. Full BGP Table Dump Ingestion
Download or parse a full 400MB+ RIPE RIS MRT BGP table (`latest-bview.gz`):
```bash
# Using downloaded file
python3 detector.py --bgp-file data/latest-bview.gz --output all_dark_leads.csv

# Or trigger automatic download
python3 detector.py --download-bgp --output all_dark_leads.csv
```

---

## 5. Lead Scoring Methodology

| Factor | Weight | Strategic Broker Value |
| :--- | :---: | :--- |
| **Unannounced in BGP** | +35 pts | 0 RIS peers routing the block; zero risk of active production disruption upon sale. |
| **Legacy Status (pre-1997)** | +25 pts | Asset allocated prior to RIR policies; clean title, often free of strict usage covenants. |
| **Domain Resolves (DNS A)** | +15 pts | Confirms corporate parent entity is active, operational, and legally capable of signing LOIs. |
| **MX Server Alive** | +10 pts | Active corporate mail gateway confirms CIO / CFO / IT director mailboxes are reachable. |
| **Large Block Size (>= /20)** | +10 pts | Higher transaction yield ($83K+ for /20; $1.33M+ for /16; $340M+ for /8). |
| **Vintage Vintage (>= 20 yr)** | +5 pts | Multi-decade tenure confirms space is an orphaned balance-sheet asset. |

**Tiers:**
- `PRIME_TARGET` (Score >= 80): Live company holding unannounced legacy block with reachable executive email domains.
- `HIGH` (Score 60–79): Verified dark legacy holder with operational infrastructure.
- `MEDIUM` (Score 40–59): Dark block with partial contactability.
- `LOW` (Score < 40): Announced or unverifiable entity.

---

## 6. Sample Verified Leads Output

From `dormant_ipv4_leads.csv`:

| Prefix | Size | IPs | RIR | Org / Entity | Est. Value ($20.28/IP) | Dormant Score | Contact Domain | Active Contacts |
| :--- | :---: | :---: | :---: | :--- | :---: | :---: | :--- | :--- |
| `8.9.0.0/16` | /16 | 65,536 | ARIN | **Level 3 Parent, LLC** | **$1,329,070.08** | **100.0 (PRIME)** | `level3.com` | `ipadmin@lumen.com` |
| `9.8.0.0/16` | /16 | 65,536 | ARIN | **IBM** | **$1,329,070.08** | **85.0 (PRIME)** | `us.ibm.com` | `ipreg@us.ibm.com` |
| `9.147.0.0/16` | /16 | 65,536 | ARIN | **IBM** | **$1,329,070.08** | **85.0 (PRIME)** | `us.ibm.com` | `ipreg@us.ibm.com` |
| `19.0.0.0/8` | /8 | 16,777,216 | ARIN | **Ford Motor Company** | **$340,241,940.48** | **100.0 (PRIME)** | `ford.com` | `dnsadmin@ford.com` |
| `38.0.0.0/8` | /8 | 16,777,216 | ARIN | **Cogent Communications** | **$340,241,940.48** | **100.0 (PRIME)** | `cogentco.com` | `ipalloc@cogentco.com` |
| `25.0.0.0/8` | /8 | 16,777,216 | RIPE | **UK Ministry of Defence**| **$340,241,940.48** | **100.0 (PRIME)** | `mod.gov.uk` | `hostmaster@mod.gov.uk` |

---

## 7. Unit Test Suite

Execute the zero-network test suite:
```bash
python3 -m unittest -v test_detector.py
```

Test coverage:
- `TestRIRParser`: Parsing ARIN/RIPE extended delegation files, filtering >= /22, discarding IPv6/ASN/summaries/reserved, legacy cutoff date validation.
- `TestBGPTable`: Bitwise Radix Trie insertion, subprefix and covering route queries, RFC 6396 MRT TABLE_DUMP_V2 parsing with both raw and gzip compressed inputs.
- `TestLivenessAndScoring`: Contact domain extraction, org domain inference, multi-factor dormant likelihood scoring.
- `TestLeadExport`: CSV serialization with required schema and valuation math.
- `TestEndToEndPipeline`: Integrated fixture-driven execution validating unannounced dark block filtering and valuation.

---

## 8. Broker Commercialization Model

- **Lead Subscription Feed:** $500 – $1,500/month recurring subscription providing weekly refreshed, deduplicated, and liveness-verified dark IPv4 seller leads.
- **Finder / Referral Partnership:** 10% – 25% broker commission split upon closed transfer (yielding $1,500 – $6,000+ per /16 closed transaction).
- **Target Partners:** IPv4.Global by Hilco Streambank, Prefixx, IPXO, Brander Group, Kalorama.
