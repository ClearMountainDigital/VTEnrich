# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

VTEnrich is a Python CLI + notebook helper that reads a CSV of IOCs, looks each one up in URLScan.io and/or VirusTotal v3, and writes an enriched CSV with a composite maliciousness verdict per row. The CLI entry point is `VTEnrich.py`; `vt_notebook.py` wraps the same primitives for interactive (Jupyter) use.

## Common commands

```bash
# Install deps (Python 3.9+, 3.10+ recommended)
python3 -m pip install -r requirements.txt

# Typical run (reads vt_config.local.json automatically if present)
python3 VTEnrich.py input.csv

# Run with explicit overrides
python3 VTEnrich.py input.csv -o out.csv --api-key KEY --rate 4 --relationships --rel-limit 5

# Reset local usage tracking (e.g. new billing month)
rm .vt_usage.json
```

There is no test suite, linter config, or build step. Iteration is by running `VTEnrich.py` against `input.csv` end-to-end.

## Architecture

All production logic lives in `VTEnrich.py`. `vt_notebook.py` imports from it — treat `VTEnrich.py` as the source of truth and avoid duplicating logic into the notebook wrapper.

### Lookup chain (`enrich_row_phase1`)

For each row, the type is resolved via `_resolve_type` (column → `default_type` config/CLI → hash detection). The chain then runs:

- **domain / url** rows:
  1. `URLScanClient.search_domain` — `urlscan_verdict_from_search` only accepts results where score≠0 OR categories non-empty OR brands non-empty AND scan timestamp is within `urlscan_stale_days`. Anything else falls through.
  2. `VTClient.get_domain` / `get_url` — VT fallback when URLScan has no usable hit.
  3. If still no signal and `submit_missing` is on, `URLScanClient.submit_url` (default visibility `unlisted`) queues a scan UUID for phase 2. The row's `verdict_source` is set to `urlscan_submit_pending`.
- **ip / file** rows: VT only (preserves legacy behavior). `file` rows additionally extract `vt_md5/sha1/sha256` from VT's response — VT is authoritative for hashes.

### Phase 2 (in `process_csv`)

After the row loop, any rows still pending submission are polled at most twice via `enrich_row_phase2`:
- Wait `poll_initial_wait` (default 20s), poll each pending scan once.
- If any are still not ready, wait `poll_second_wait` (default 30s), poll once more.
- Remaining unresolved rows are marked `urlscan_submit_timeout`. Cap of 2 polls per scan keeps total Result Retrieve calls well under URLScan's daily quota even when fallback fires often.

### Output schema

Per-row output columns added (on top of original input columns):
- Provider-specific: `urlscan_score`, `urlscan_categories`, `urlscan_brands`, `urlscan_scan_date`, `urlscan_scan_id`, `urlscan_permalink`, plus all `vt_*` fields.
- Synthesized: `verdict_source` (one of `urlscan_search` / `virustotal` / `urlscan_submit` / `urlscan_submit_pending` / `urlscan_submit_timeout` / `none`), `maliciousness_score` (0–100 from `compute_composite_verdict`), `verdict_summary`.

### Score formula
`compute_composite_verdict`: if URLScan score present → `(urlscan_score + 100) / 2`; else if VT has detection counts → `100 * malicious / (malicious + suspicious + harmless + undetected)`; else null. Thresholds for `verdict_summary`: `malicious` ≥ 50, `suspicious` ≥ 20, `benign` < 20.

### Rate limiting

- `VTClient` paces with a fixed `60/rate_per_min` interval (default 4/min) and honors `Retry-After` on 429.
- `URLScanClient` is header-driven: every response's `X-Rate-Limit-Remaining` and `X-Rate-Limit-Reset-After` are read in `_apply_rate_headers`; when remaining is low, the next call is delayed to spread the budget across the reset window. 429 responses honor `Retry-After`. Per URLScan docs, **only HTTP 200 responses count against quota**, so `_request` bumps `UsageTracker` only on 200.

### Checkpoint

`Checkpoint` writes the per-row enriched dict to a sidecar JSON keyed by `<row_idx>::<ioc>`. Atomic write via `tempfile.mkstemp` + `os.replace`. The checkpoint stores a SHA-256 fingerprint of the input file; if the input changes between runs, loading the checkpoint raises an error (refuses to silently resume onto wrong rows). Rows with `verdict_source == "urlscan_submit_pending"` are kept on disk so phase 2 can resume after `Ctrl-C`.

### Usage tracking

`UsageTracker` is per-machine and now per-action (`vt`, `urlscan_search`, `urlscan_submit`, `urlscan_retrieve`), each with daily and monthly counters in `actions.<action>.{daily,monthly}` inside `.vt_usage.json`. Legacy state files (top-level `daily` / `monthly` only) auto-migrate to `actions.vt` on first load. Top-level legacy counters are still mirrored for VT bumps so older readers keep working. `caps` dict (passed at construction) drives `remaining(action, window)` queries used in the preflight table.

### Config precedence

CLI > env (`VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY`) > config JSON > built-in defaults. `_load_config` searches `--config` path, then `vt_config.local.json`, then `vt_config.json` in cwd. Effective values are reduced in `_resolve_effective`.

### Output layout
Outputs default to `out/<YYYY-MM-DD>/<input_base>.<session_id>.enriched.csv`; logs to `logs/<YYYY-MM-DD>/vt_enrich_<session_id>.log`. `session_id` is `YYYYMMDD-HHMMSS-<6hex>`. A user-supplied `-o` that is a directory or non-`.csv` path is treated as a directory; a `.csv` path is used verbatim.

## Conventions specific to this codebase

- **Type resolution**: `default_type` is the primary way to handle inputs without a type column (e.g. a flat subdomain list). If neither a type column nor `default_type` is set, preflight raises with a clear error. The legacy positional `TYPE_COL_INDEX=4` is still used as a last-resort fallback when the CSV is wide enough.
- `TYPE_NORMALIZATION` is the canonical mapping from free-form labels to internal types (`domain`, `url`, `ip`, `file`). Add new aliases there.
- URL IDs for VT must be `urlsafe_b64encode` of the URL with `=` padding stripped — see `vt_url_id`. VT requires that exact form.
- URLScan search query is `page.domain:"<d>"` — matches scans where the IOC was the loaded page. `domain:` would match third-party requests on other pages, which is the wrong semantic for verdicts.
- Default URLScan submission visibility is `unlisted`. Don't change to `public` by default — submissions may contain sensitive subdomains from threat-hunting lists. The user-facing flag is `--urlscan-visibility`.
- Free-tier rate limits are real. Default `rate_per_min=4` exists because higher rates trigger 429s with free VT keys. URLScan pacing is header-driven, so no hardcoded rate there — trust the headers.
- The `.vt_usage.json`, `vt_config.local.json` / `vt_config.json`, `out/`, `logs/`, and any `*.checkpoint.json` files contain secrets / quota state / partial runs. All are gitignored; never commit them.
- The notebook (`vt_notebook.py`) intentionally disables `submit_missing` because it has no phase-2 polling loop. Big jobs go through the CLI.
