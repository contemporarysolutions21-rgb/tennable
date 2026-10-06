# NVD Asset Vulnerability Matching MVP

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
python nvd_asset_vulnerability_mvp.py   --input financial_services_dummy_asset_inventory.xlsx   --output nvd_test_findings.xlsx   --max-assets 10
```

## Run all 1,000 assets

```bash
python nvd_asset_vulnerability_mvp.py   --input financial_services_dummy_asset_inventory.xlsx   --output nvd_vulnerability_findings.xlsx
```

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
