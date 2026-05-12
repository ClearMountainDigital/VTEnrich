# VTEnrich — Enrich a CSV with VirusTotal + URLScan Data

VTEnrich reads a CSV of indicators (domains, subdomains, URLs, IPs, file hashes), looks each one up against URLScan.io and VirusTotal, and writes a new CSV with a maliciousness verdict, raw provider signals, and a composite score per row.

It is designed around free-tier rate limits — it paces calls automatically, tracks usage on disk, and is resumable across days so you can leave a long job, stop it, and pick up where you left off without burning quota twice.

## Highlights

- **Two providers, one chain.** For each domain or URL, the tool tries URLScan Search first (cheap), falls back to VirusTotal, and (optionally) submits a fresh URLScan scan as a last resort. IPs and file hashes use VT only.
- **Honest sourcing.** Every output row carries a `verdict_source` column (`urlscan_search` / `virustotal` / `urlscan_submit` / `urlscan_submit_pending` / `urlscan_submit_timeout` / `none`) so you can always see where a signal came from.
- **Composite score.** Each row gets a `maliciousness_score` (0–100) and `verdict_summary` (`malicious` / `suspicious` / `benign` / `unknown`), computed from whichever provider answered.
- **Free-tier aware.** VirusTotal calls are paced (default 4/min). URLScan calls self-pace by reading the provider's own `X-Rate-Limit-*` response headers per action.
- **Resumable.** A sidecar checkpoint file is written atomically after every completed row. Restarting skips finished rows and resumes pending URLScan submissions. The checkpoint is fingerprinted to the input file so you can't accidentally resume onto the wrong CSV.

## Requirements

- macOS, Linux, or Windows
- Python 3.9+ (3.10+ recommended)
- A VirusTotal API key (free is fine)
- An URLScan.io API key (free is fine; optional but strongly recommended — it raises your effective daily throughput considerably)

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python3 -m pip install -r requirements.txt
```

## Get your API keys

- **VirusTotal**: create a free account at virustotal.com, then copy the API key from your profile settings.
- **URLScan.io**: create a free account at urlscan.io, then copy the API key from your user profile.

Provide each key one of three ways (highest priority wins):

1. CLI flags: `--api-key YOUR_VT_KEY` / `--urlscan-api-key YOUR_URLSCAN_KEY`
2. Environment variables: `VIRUSTOTAL_API_KEY` / `URLSCAN_API_KEY`
3. A config file (see below) under `api_key` / `urlscan_api_key`

## Configuration file (recommended)

A JSON config lets you set sensible defaults once. The tool auto-loads (in order): the `--config` path → `vt_config.local.json` → `vt_config.json` in the current directory.

Copy `vt_config.example.json` to `vt_config.local.json` (gitignored) and fill in the values:

```json
{
  "api_key": "PUT_YOUR_VIRUSTOTAL_API_KEY_HERE",
  "urlscan_api_key": "PUT_YOUR_URLSCAN_API_KEY_HERE",

  "rate_per_min": 4,
  "timeout": 30,

  "daily_cap": 500,
  "monthly_cap": 15500,

  "ioc_col": "Query",
  "default_type": "domain",

  "use_urlscan": true,
  "urlscan_submit_missing": true,
  "urlscan_visibility": "unlisted",
  "urlscan_stale_days": 90,

  "urlscan_search_daily_cap": 1000,
  "urlscan_submit_daily_cap": 1000,
  "urlscan_submit_hourly_cap": 100
}
```

Precedence: **CLI flags > environment variables > config file > built-in defaults.**

## Input CSV format

You have three ways to point the tool at your IOC values. Pick whichever fits your file.

### 1. Flat list of domains/subdomains (most common)

If your file is just domains with maybe a "last seen" column, set `--default-type domain` and tell it which column holds the IOC:

```csv
Query,Last Seen
mail.example.com,2025-01-01T00:00:00Z
api.example.com,2025-01-01T00:00:00Z
```

```bash
python3 VTEnrich.py subdomains.csv --ioc-col Query --default-type domain
```

(Or set `ioc_col: "Query"` and `default_type: "domain"` in your config and just run `python3 VTEnrich.py subdomains.csv`.)

### 2. CSV with explicit IOC + type columns

```csv
id,notes,ioc,type,other
1,homepage,example.com,DOMAIN,foo
2,suspicious,https://bad.example/path,URL,bar
3,origin,8.8.8.8,IP,baz
4,file hash,44d88612fea8a8f36de82e1278abb02f,MD5,qux
```

```bash
python3 VTEnrich.py mixed.csv --ioc-col ioc --type-col type
```

Accepted values for the type column: `DOMAIN`, `URL` / `URI`, `IPV4` / `IP`, `MD5` / `SHA1` / `SHA256` / `FILE`.

### 3. By column position

The legacy default — IOC at column C (index 2), type at column E (index 4). Used when neither `--ioc-col` nor `--default-type` is set.

```bash
python3 VTEnrich.py legacy.csv     # reads C and E by position
```

## How verdicts are produced

For each **domain or URL** row, the tool runs this chain and stops at the first provider with a usable answer:

1. **URLScan Search** (`/api/v1/search/?q=page.domain:"<ioc>"`). A hit is "usable" if it has a non-zero `verdicts.urlscan.score`, a non-empty `categories` list, or a non-empty `brands` list, AND the scan is newer than `--urlscan-stale-days` (default 90).
2. **VirusTotal** (`/api/v3/domains/{d}` or `/urls/{id}`). Used when URLScan returns nothing usable.
3. **URLScan submission** (`/api/v1/scan/`, default visibility `unlisted`). Only runs when `--urlscan-submit-missing` is enabled. The scan ID is queued and polled in a second pass at end of run (at most 2 polls per scan).

For **IP and file hash** rows, only VirusTotal is queried.

After phase 1 walks every row, phase 2 polls any queued URLScan submissions:

- Initial wait of 20s, then one poll per pending scan.
- Any scans still not ready get a single second poll after another 30s wait.
- Anything still not ready is marked `urlscan_submit_timeout` — re-run the tool later and the checkpoint will resume polling.

## Maliciousness score

`maliciousness_score` is a single 0–100 value (higher = more malicious):

- **URLScan present and ≠ 0**: `score = (urlscan_score + 100) / 2`. URLScan reports −100 (legitimate) to +100 (malicious); a +60 phishing rating maps to 80.
- **URLScan absent or score == 0** (no opinion): fall back to VT counts. `score = 100 × malicious / (malicious + suspicious + harmless + undetected)`.
- **Neither provider has data**: empty.

`verdict_summary` is bucketed from the score:
- `malicious` — score ≥ 50
- `suspicious` — score ≥ 20
- `benign` — score < 20
- `unknown` — no score could be computed

## Resumability

Every completed row is written to a sidecar checkpoint file (`<output>.checkpoint.json` by default) atomically as soon as it finishes. On restart:

- Already-completed rows are skipped — no API calls.
- Rows that were left as `urlscan_submit_pending` get re-polled in phase 2.
- The checkpoint records a SHA-256 of the input file. If you swap the input for a different file but point to the same checkpoint, the run aborts with a clear error rather than silently mixing rows.

To start fresh on the same input, either pass `--no-resume` or delete the `.checkpoint.json` file. To branch checkpoints (e.g. a parallel experimental run), pass `--checkpoint /some/other/path.json`.

## Running

The simplest case, assuming a `vt_config.local.json` is in place:

```bash
python3 VTEnrich.py subdomains.csv
```

A safer first run on any new dataset — process just 1 row to confirm the output columns look right before committing to the full job:

```bash
python3 VTEnrich.py subdomains.csv --limit 1
```

Override config from the CLI:

```bash
python3 VTEnrich.py subdomains.csv \
  -o /path/to/output.csv \
  --api-key YOUR_VT_KEY \
  --urlscan-api-key YOUR_URLSCAN_KEY \
  --default-type domain \
  --urlscan-stale-days 90 \
  --no-urlscan-submit          # if you'd rather not submit fresh scans
```

VT-only run (no URLScan key, or you've decided to skip it):

```bash
python3 VTEnrich.py subdomains.csv --no-urlscan --default-type domain
```

By default, output goes to `out/<YYYY-MM-DD>/<input>.<session>.enriched.csv` and logs go to `logs/<YYYY-MM-DD>/vt_enrich_<session>.log`. Pass `-o` to choose your own path.

## Output columns

Your original CSV columns are preserved. The tool appends the following.

### Synthesized verdict (one per row)

- `verdict_source` — which provider produced the primary signal (see list above).
- `maliciousness_score` — 0–100 composite (higher = more malicious).
- `verdict_summary` — `malicious` / `suspicious` / `benign` / `unknown`.
- `normalized_type` — the internal type (`domain` / `url` / `ip` / `file`).
- `derived_domain_from_url` — for URL IOCs, the registered domain extracted from the URL.
- `additional_iocs` — JSON list of related IOCs (e.g. a URL's parsed domain, or VT-derived resolutions if `--relationships` is on).

### URLScan columns

- `urlscan_score` — raw URLScan maliciousness score (−100 to +100).
- `urlscan_categories` — comma-separated category tags (e.g. `phishing`).
- `urlscan_brands` — comma-separated brand detections.
- `urlscan_scan_date` — ISO-8601 timestamp of the chosen scan.
- `urlscan_scan_id` — UUID of the chosen scan (or submission).
- `urlscan_permalink` — link to the scan result in URLScan's web UI.

### VirusTotal columns

- `vt_http_status` — HTTP status from VT (200, 404, etc.).
- `vt_permalink` — link to the item in VT's web UI.
- `vt_reputation` — VT's reputation score.
- `vt_last_analysis_date` — last analysis time (epoch seconds).
- `vt_stats_malicious`, `vt_stats_suspicious`, `vt_stats_harmless`, `vt_stats_undetected` — engine detection counts.
- `vt_tags` — comma-separated tags from VT.
- `vt_categories` — comma-separated categories from VT.
- `vt_first_submission_date`, `vt_last_modification_date` — VT lifecycle timestamps.
- `vt_error` — error message if something went wrong for this row.

### File hash columns (only meaningful for file IOCs)

- `vt_md5`, `vt_sha1`, `vt_sha256` — hashes from VT's response. VT is authoritative; these come from the lookup, not the input.
- `sha1_from_vt`, `sha256_from_vt` — convenience mirrors (blank if VT didn't return the hash).

## Relationships (optional)

`--relationships` (off by default) makes VT fetch related IOCs and writes them as JSON into `additional_iocs`:

- For `domain`: resolved IPs
- For `ip`: resolved domains
- For `file`: contacted domains and contacted IPs

Each related entry has the form `{"type": "...", "value": "...", "source": "vt_resolutions" | "vt_contacted_domains" | ...}`. Use `--rel-limit N` to cap items per row (default 5). Relationships cost extra VT calls; avoid on free keys unless you need them.

## Rate limits and usage tracking

The tool writes per-action counters to a local JSON file (default `.vt_usage.json`):

- `vt` — VirusTotal calls
- `urlscan_search` / `urlscan_submit` / `urlscan_retrieve` — URLScan calls per action

Each has daily and monthly counters. The preflight panel shown at the start of a run reports remaining capacity per provider and warns if the run would likely exceed a daily cap. The tracker is per-machine (no cloud sync). Delete `.vt_usage.json` to reset.

Per URLScan's docs, only successful (HTTP 200) URLScan responses count against quota — that's what the tracker reflects. URLScan pacing is header-driven: the tool reads `X-Rate-Limit-Remaining` and `X-Rate-Limit-Reset-After` on every response and self-throttles per action.

VT calls are paced to `--rate` per minute (default 4). Free VT keys reliably 429 above this; the tool does honor `Retry-After` if it slips through.

## Smoke test before a big run

Before running thousands of rows, always do a one-row smoke test against your actual file:

```bash
python3 VTEnrich.py your_input.csv --limit 1
```

Confirm:
- `verdict_source` is one of the expected values (not `none` for every row).
- `maliciousness_score` is populated where you'd expect.
- URLScan / VT columns look sensible.

If your dataset is likely to include obscure or fresh subdomains that neither URLScan nor VT have seen, also do a `--limit 1` against one of those rows to exercise the submission + phase-2 polling path end-to-end. A success looks like `verdict_source: urlscan_submit` with a numeric score on completion.

## Troubleshooting

- **`ModuleNotFoundError: No module named 'pandas'`** — run `python3 -m pip install -r requirements.txt`.
- **`VIRUSTOTAL_API_KEY is not set`** — export the variable, pass `--api-key`, or set `api_key` in your config.
- **`No type column found and --default-type not set`** — your input has no usable type column. Pass `--default-type domain` (or whichever type fits) or `--type-col <name>`.
- **`Checkpoint ... was created for a different input file`** — the checkpoint sidecar fingerprints the input. Either delete `<output>.checkpoint.json` or point `--checkpoint` somewhere else.
- **Lots of `urlscan_submit_timeout`** — URLScan scans can take 30s+ to finish. Re-run the same command; the checkpoint will re-poll any pending IDs without re-submitting.
- **Slow runs** — that's the rate limiter doing its job on a free key. Don't raise `--rate` above 4 without a paid VT plan; you'll just get 429s.

## Safety and privacy

The tool sends your IOC values to VirusTotal and URLScan to retrieve results. Don't run it on data you aren't allowed to share with those services. URLScan submissions are made as `unlisted` by default — they're not in the public feed, but they're still hosted by URLScan and visible to anyone with the scan link. Use `--urlscan-visibility private` (URLScan Pro) for stricter handling, or `--no-urlscan-submit` to avoid submitting anything at all.

## Quick command reference

```bash
python3 VTEnrich.py INPUT.csv \
  [-o OUTPUT.csv] [--config PATH] \
  [--api-key VT_KEY] [--urlscan-api-key URLSCAN_KEY] \
  [--ioc-col SELECTOR] [--type-col SELECTOR] [--default-type {domain,url,ip,file}] \
  [--urlscan | --no-urlscan] \
  [--urlscan-submit-missing | --no-urlscan-submit] \
  [--urlscan-visibility {public,unlisted,private}] \
  [--urlscan-stale-days N] \
  [--rate N] [--timeout SECONDS] \
  [--relationships | --no-relationships] [--rel-limit N] \
  [--daily-cap N] [--monthly-cap N] [--usage-state PATH] \
  [--output-dir DIR] [--logs-dir DIR] \
  [--limit N] [--checkpoint PATH] [--resume | --no-resume]
```

| Flag | Purpose | Default |
| --- | --- | --- |
| `--api-key` / `--urlscan-api-key` | API keys (or set env / config) | — |
| `--ioc-col` / `--type-col` | Column selectors (header name, letter, or index) | `Query` then column C / column E or absent |
| `--default-type` | Type to apply to every row when no type column | unset |
| `--urlscan` / `--no-urlscan` | Enable URLScan as primary lookup | on |
| `--urlscan-submit-missing` / `--no-urlscan-submit` | Submit fresh URLScan scans on misses | on |
| `--urlscan-visibility` | Submission visibility | `unlisted` |
| `--urlscan-stale-days` | URLScan hit older than this is treated as miss | 90 |
| `--rate` | VT requests per minute | 4 |
| `--daily-cap` / `--monthly-cap` | VT quota tracking | 500 / 15500 |
| `--limit` | Process only the first N rows | unset |
| `--checkpoint` | Path to checkpoint sidecar | `<output>.checkpoint.json` |
| `--resume` / `--no-resume` | Reuse or discard checkpoint | resume |
| `--relationships` / `--rel-limit` | Fetch VT-related IOCs | off / 5 |
| `--output-dir` / `--logs-dir` | Base dirs for date-bucketed outputs/logs | `out` / `logs` |
| `--usage-state` | Local usage tracking JSON | `.vt_usage.json` |

## Where the code lives

- `VTEnrich.py` — single file: `VTClient`, `URLScanClient`, `UsageTracker`, `Checkpoint`, the two-phase enrichment pipeline, and the CLI.
- `vt_notebook.py` — thin wrapper around the same primitives for Jupyter / REPL use. (The notebook intentionally skips URLScan submission fallback — use the CLI for big jobs that need it.)
