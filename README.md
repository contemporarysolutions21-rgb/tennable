# CVE Sherlock

CVE Sherlock is an agent that pulls CVEs from the NIST National Vulnerability Database (NVD) and compares them against an asset inventory to identify assets that are probably vulnerable.

This package matches the supplied financial-services asset inventory against the NIST National Vulnerability Database (NVD) using the NVD 2.0 CPE and CVE APIs.

## What it does

1. Reads `Asset Inventory` from the supplied Excel workbook.
2. Normalizes vendor, product, and version fields.
3. Resolves candidate CPE names through the NVD CPE 2.0 API.
4. Queries NVD CVEs for the strongest candidate CPEs.
5. Evaluates NVD applicability criteria and version ranges.
6. Assigns a confidence level and business-oriented risk priority.
7. Writes `Vulnerability Findings`, `Normalized Assets`, `Errors`, and `Run Summary` sheets.

**Important:** A finding is labeled `PROBABLE - VALIDATE`. Inventory data is not proof that a vulnerable version is actually installed or exposed.

## Repository layout

```
.
├── nvd_asset_vulnerability_mvp.py          # the matching agent
├── requirements.txt
├── scripts/
│   └── generate_vulnerable_inventory.py    # builds the vulnerable test inventory
└── data/
    ├── financial_services_dummy_asset_inventory.xlsx   # 1,000 randomized assets
    └── vulnerable_asset_inventory.xlsx                 # 30 assets seeded with real CVEs + answer key
```

## Prerequisites

- Python 3.10+
- Network access to `services.nvd.nist.gov`
- An [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (optional, but strongly recommended: without one NVD rate-limits requests heavily)
- An asset inventory `.xlsx` with an `Asset Inventory` sheet containing at least `Asset ID`, `Asset Name`, `Vendor`, `Asset Subtype` and `Version / Firmware` columns (see the files in `data/`)

## Setup

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Set your NVD API key if you have one:

```bash
export NVD_API_KEY="YOUR_NVD_API_KEY"
```

Windows PowerShell:

```powershell
$env:NVD_API_KEY="YOUR_NVD_API_KEY"
```

## Test with 10 assets

```bash
python nvd_asset_vulnerability_mvp.py  --input data/financial_services_dummy_asset_inventory.xlsx  --output nvd_test_findings.xlsx  --max-assets 10
```

## Run all 1,000 assets

```bash
python nvd_asset_vulnerability_mvp.py  --input data/financial_services_dummy_asset_inventory.xlsx  --output nvd_vulnerability_findings.xlsx
```

## Outputs

The agent writes an Excel workbook (default `nvd_vulnerability_findings.xlsx`) with four sheets:

| Sheet | Contents |
|-------|----------|
| `Vulnerability Findings` | One row per asset/CVE match: CVE ID, CVSS score and severity, description, matched NVD CPE criteria, match type, confidence (70 or 95), evidence, business risk priority, and `PROBABLE - VALIDATE` status |
| `Normalized Assets` | Each asset's normalized vendor/product/version, candidate CPEs, or `No strong CPE candidate` |
| `Errors` | Assets whose NVD lookups failed, with the error |
| `Run Summary` | Run timestamp, asset/finding/error counts, and whether an API key was used |

## Outbound data flows

CVE Sherlock makes HTTPS GET requests to one external service only:

| Destination | What is sent | Why |
|-------------|--------------|-----|
| `services.nvd.nist.gov` (NVD CPE 2.0 and CVE 2.0 APIs) | Normalized vendor and product names from the inventory (e.g. `apache:log4j`), candidate CPE names, and your NVD API key in the `apiKey` header if one is set | Resolve CPEs and retrieve applicable CVEs |

No other asset fields (hostnames, IP addresses, owners, data classification, etc.) leave your machine. All results are written to a local Excel file.

## Known limitations

- **Findings are probable, not confirmed.** Matches are based on inventory data and NVD applicability; validate against the actual installed software and patch level.
- **Application CPEs only.** CPE lookup queries `part = a`, so operating systems and firmware (Windows, FortiOS, PAN-OS, etc.) are not resolved.
- **First 100 CPE candidates only.** For products with long version histories (e.g. Apache HTTP Server, Tomcat) the exact-version CPE may fall outside the first page, which can cause missed or lower-confidence findings.
- **Loose version comparison.** Non-PEP 440 versions such as `1.0.1f` or `8.9p1` are compared on their numeric parts only, so letter suffixes are ignored.
- **Name normalization is heuristic.** Vendor/product names must normalize to the NVD CPE vendor/product (see `VENDOR_ALIASES` and `PRODUCT_ALIASES`); unmapped names produce no finding.
- **Rate limits.** Large inventories take a long time without an NVD API key.

## Notes on the synthetic inventory

The supplied dummy inventory deliberately contains randomized vendor/product/version combinations, so some records will not resolve to meaningful NVD CPEs. This is useful for testing the agent's "no strong CPE candidate" and review paths.

For a production implementation, add structured fields for:

- Product Name
- Product Version
- Product Edition
- Patch Level
- CPE Name
- Internet Facing
- Installed Package
- Firmware Version
- Container Image
- Cloud Service

## Recommended next step

Add a human-review table for unresolved CPEs. Once a reviewer maps an asset/product to a CPE, persist that mapping and reuse it on future runs. This prevents repeated fuzzy resolution and improves accuracy over time.

## NVD references

NVD's 2.0 APIs are the preferred mechanism for current NVD automation. The CPE API provides the Official CPE Dictionary, while the CVE API supports CPE-based vulnerability searching and applicability data.

See:
- https://nvd.nist.gov/developers/products
- https://nvd.nist.gov/vuln/data-feeds

## Vulnerable test inventory

`data/vulnerable_asset_inventory.xlsx` is a 30-asset dummy inventory (same
`Asset Inventory` schema) seeded with software versions that carry real,
publicly known NVD CVEs (Log4Shell, Spring4Shell, MOVEit, Confluence OGNL,
Jenkins CLI, regreSSHion, etc.). Its `Expected Findings` sheet is the answer
key, including 5 negative controls (patched versions and in-house software).

Regenerate it with:

```bash
python scripts/generate_vulnerable_inventory.py --output data/vulnerable_asset_inventory.xlsx
```

Run the agent against it:

```bash
python nvd_asset_vulnerability_mvp.py --input data/vulnerable_asset_inventory.xlsx --output vulnerable_findings.xlsx
```
