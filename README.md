## VTEnrich — Enrich a CSV with VirusTotal Data

VTEnrich is a simple command‑line tool that reads a CSV file, looks up each Indicator of Compromise (IOC) in VirusTotal, and writes a new CSV with many helpful VirusTotal fields added.

If you have a list of IOCs (like domains, URLs, IPs, or file hashes) and want quick context from VirusTotal, this tool saves time.

### What this tool does (plain language)
- **Reads your CSV** and picks two columns by position: the IOC in column C and the IOC type in column E.
- **Calls VirusTotal** at a safe pace to avoid rate limits.
- **Adds new columns** with VirusTotal results (reputation, detections, tags, dates, etc.).
- **Optionally** adds related IOCs (for example, IPs that a domain resolves to) if you enable relationships.
- **Writes a new CSV** so you keep your original file unchanged.

### Who is this for?
Anyone who needs fast VirusTotal context for a list of IOCs, especially analysts and researchers. No coding experience is required.

---

### Requirements
- macOS, Linux, or Windows
- Python 3.9+ (3.10+ recommended)
- A VirusTotal API key (free keys work, but they have strict rate limits)

### Install (one‑time setup)
In a terminal:

```bash
# 1) (Optional) Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 2) Install dependencies
python3 -m pip install -r requirements.txt
```


### Get your VirusTotal API key
1) Create a free account on the VirusTotal website (search for “VirusTotal”).
2) After signing in, go to your profile/settings page.
3) Find your API key and copy it. Keep it private.

You can provide the key in three ways (highest priority first):
1) Pass `--api-key YOUR_KEY` on the command line
2) Set an environment variable `VIRUSTOTAL_API_KEY`
3) Put it in a config file (`vt_config.local.json` or `vt_config.json`)

---

### Configuration file (recommended)
You can store defaults in a JSON file so new users don’t have to remember all the flags.

Files the tool will look for automatically, in this order:
- A path you pass via `--config`
- `vt_config.local.json` (preferred for your personal machine; ignored by Git)
- `vt_config.json` (shared defaults; also ignored by Git)

Example `vt_config.example.json` (provided in the repo):

```json
{
  "api_key": "PUT_YOUR_VIRUSTOTAL_API_KEY_HERE",
  "rate_per_min": 4,
  "timeout": 30,
  "relationships": false,
  "relationships_limit": 5,
  "daily_cap": 500,
  "monthly_cap": 15500,
  "usage_state_file": ".vt_usage.json",
  "output_dir": "out",
  "logs_dir": "logs"
}
```

To use this:
1) Copy `vt_config.example.json` to `vt_config.local.json`
2) Edit the values (at least `api_key`)
3) Run the tool normally (you can still override any value with CLI flags)

Priority (what wins if values conflict):
- CLI flags > environment variables > config file > built‑in defaults

### Input CSV format (very important)
This tool reads your CSV **by position**, not by header names:
- IOC value must be in **column C** (0-based index 2)
- IOC type must be in **column E** (0-based index 4)

Your CSV can have headers or not — that’s fine. The tool only cares about positions.

Accepted IOC types (column E):
- DOMAIN
- URL or URI
- IPV4 or IP
- MD5, SHA1, SHA256, or FILE (for file hashes)

Example input (headers are optional):

```csv
id,notes,ioc,type,other
1,homepage,example.com,DOMAIN,foo
2,suspicious,https://bad.example/path,URL,bar
3,origin,8.8.8.8,IP,baz
4,file hash,44d88612fea8a8f36de82e1278abb02f,MD5,qux
```

If your file does not have at least 5 columns, or the IOC/type columns are not located in C and E, the tool will error. Move/duplicate columns as needed.

---

### How to run

Option A — set the environment variable once for your terminal session:

```bash
export VIRUSTOTAL_API_KEY=YOUR_KEY_HERE
python3 VTEnrich.py /path/to/input.csv
```

Option B — pass the key directly every time:

Option C — use a config file:

```bash
# If you created vt_config.local.json, no extra flags are needed
python3 VTEnrich.py /path/to/input.csv

# Or specify a custom config path
python3 VTEnrich.py /path/to/input.csv --config /path/to/my_config.json
```

You can also set usage caps and state file via CLI or config for planning/tracking:

```bash
python3 VTEnrich.py input.csv \
  --daily-cap 500 \
  --monthly-cap 15500 \
  --usage-state .vt_usage.json
```

```bash
python3 VTEnrich.py /path/to/input.csv --api-key YOUR_KEY_HERE
```

By default, output is written under a dated folder with a unique session name, e.g. `out/2025-01-15/<input>.<session>.enriched.csv`.

Choose a custom output path:

```bash
python3 VTEnrich.py /path/to/input.csv -o /path/to/output.csv
```

Useful performance flags (especially for free API keys):

```bash
# Pace to ~4 requests/min (default). Safer for free keys.
--rate 4

# HTTP timeout per request (seconds). Default: 30
--timeout 30

# Fetch related IOCs (e.g., domain → IP resolutions, file → contacted domains/IPs)
# This uses more API calls. Use with care on free keys.
--relationships

# Limit the number of related IOCs fetched per item (default: 5)
--rel-limit 5
```

Full example:

```bash
python3 VTEnrich.py \
  /path/to/input.csv \
  -o /path/to/output.csv \
  --api-key YOUR_KEY_HERE \
  --rate 4 \
  --timeout 30 \
  --relationships \
  --rel-limit 5
```

---

### What you’ll get in the output
Your original CSV columns are preserved, plus these new columns:

- `normalized_type`: The cleaned IOC type the tool uses internally (like `domain`, `url`, `ip`, `file`).
- `derived_domain_from_url`: If the IOC is a URL, this is the domain pulled from the URL.
- `additional_iocs`: A JSON list of related IOCs, when available (see “Relationships” below).

VirusTotal summary columns (when available):
- `vt_http_status`: HTTP status code from VirusTotal (200, 404, etc.).
- `vt_permalink`: Link to the item in VirusTotal’s web UI.
- `vt_reputation`: VT’s reputation score.
- `vt_last_analysis_date`: Last analysis time (epoch seconds).
- `vt_stats_malicious`, `vt_stats_suspicious`, `vt_stats_harmless`: Detection counts from AV engines.
- `vt_tags`: Comma‑separated tags returned by VT.
- `vt_categories`: Comma‑separated categories returned by VT.
- `vt_first_submission_date`: First time VT saw the item.
- `vt_last_modification_date`: Last update time for the item.
- `vt_error`: Error message if something went wrong (for example, no data).

File hash convenience columns (for file IOCs):
- `vt_md5`, `vt_sha1`, `vt_sha256`: Hashes from VT (these are authoritative).
- `sha1_from_vt`, `sha256_from_vt`: Mirrors for easier consumption (or blank if missing).

Example `additional_iocs` value (as JSON in a CSV cell):

```json
[{"type": "ip", "value": "1.2.3.4", "source": "vt_resolutions"}]
```

---

### Relationships (optional)
When you add `--relationships`, the tool may add related IOCs to `additional_iocs`:
- For `domain`: resolved IPs
- For `ip`: resolved domains
- For `file`: contacted domains and contacted IPs

Note: relationships use extra API calls and may be slow or limited on free keys. Use `--rel-limit` to control volume.

---

### Handling limits and errors
- Free API keys are heavily rate‑limited. The default `--rate 4` helps avoid `429 Too Many Requests` errors.
- If a row has no data in VT, `vt_error` will say something like “No Data”. This is normal for rare or brand‑new IOCs.
- Network hiccups or timeouts will show up in `vt_error` as well.

---

### Troubleshooting
- “ModuleNotFoundError: No module named 'pandas'” → Run `python3 -m pip install -r requirements.txt`.
- “VIRUSTOTAL_API_KEY is not set” → Either export the variable or pass `--api-key`.
- “Input file must have at least … columns” → Make sure your IOC is in column C and IOC type is in column E.
- CSV opens but looks wrong → Check for unusual delimiters; ensure it’s a standard comma‑separated CSV.
- Very slow runs → Lower `--relationships` usage, raise `--rate` only if you have a higher‑tier API key.

---

### Tips for best results
- Clean your input values (no leading/trailing spaces).
- Use clear IOC types (DOMAIN, URL, IP, MD5, SHA1, SHA256, FILE).
- For large files, try running in smaller chunks to respect rate limits.

---

### Command reference (quick)

```bash
python3 VTEnrich.py INPUT.csv \
  [-o OUTPUT.csv] \
  [--config PATH] \
  [--api-key KEY] \
  [--ioc-col SELECTOR] \
  [--type-col SELECTOR] \
  [--rate N] \
  [--timeout SECONDS] \
  [--relationships | --no-relationships] \
  [--rel-limit N] \
  [--daily-cap N] \
  [--monthly-cap N] \
  [--usage-state PATH] \
  [--output-dir DIR] \
  [--logs-dir DIR]
```

Arguments:
- `INPUT.csv` (required): Path to your CSV. IOC must be in column C; type in column E.
- `-o, --output`: Output CSV path. Default is `<input>.enriched.csv`.
- `--config`: Path to a JSON config file. If omitted, the tool looks for `vt_config.local.json` then `vt_config.json`.
- `--api-key`: VirusTotal API key (or set `VIRUSTOTAL_API_KEY`).
- `--rate`: Requests per minute. Default: 4 (configurable via config/env/CLI).
- `--timeout`: HTTP timeout in seconds. Default: 30 (configurable via config/env/CLI).
- `--relationships` / `--no-relationships`: Enable/disable fetching related IOCs.
- `--rel-limit`: Max related IOCs per item. Default: 5.
- `--daily-cap`: Daily request quota used for estimation/tracking. Default: 500.
- `--monthly-cap`: Monthly request quota used for estimation/tracking. Default: 15500.
- `--usage-state`: Path to a local JSON file where usage is persisted. Default: `.vt_usage.json`.
- `--output-dir`: Base directory for outputs. Files are stored under `<output-dir>/<YYYY-MM-DD>/`. Default: `out`.
- `--logs-dir`: Base directory for logs. Logs are stored under `<logs-dir>/<YYYY-MM-DD>/`. Default: `logs`.

---

### Output organization and logging
- Outputs are saved in date-based folders for easy tracking, e.g., `out/2025-01-15/<input>.<session>.enriched.csv`.
- Logs are written to `logs/<YYYY-MM-DD>/vt_enrich_<session>.log` with detailed DEBUG info.
- The console shows a progress bar, estimates, and a summary using a clean, readable layout.

---

### Preflight estimate, caps, and usage tracking
When you run the tool, it will:
- Read the input file and count rows
- Estimate total runtime based on `--rate`
- Check your remaining daily and monthly capacity using the local usage file
- Warn you if the run would exceed daily or monthly caps

How usage is tracked:
- Each API request increments counters in a local JSON file (default `.vt_usage.json`).
- Counters are grouped by day and by month.
- If you run on multiple machines, each machine’s file is separate. There is no server or cloud sync.

Resetting counts:
- Delete the `.vt_usage.json` file if you need to reset local counts (e.g., at the start of a new billing period). The file will be recreated automatically.

---

### Safety and privacy
This tool sends your IOC values to VirusTotal to get results. Only run it on data you are allowed to share with VirusTotal. Check your organization’s policies before using external enrichment services.

---

### Where to look in the code (optional)
- `VTEnrich.py` contains everything: the VirusTotal client, row enrichment, CSV processing, and the CLI.


