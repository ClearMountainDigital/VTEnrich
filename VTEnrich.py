# -----------------------------------
# Standard Library Imports
# -----------------------------------
import argparse
import os
import re
import csv
import json
import time
from datetime import datetime, date
import base64
from urllib.parse import urlparse
import logging
import uuid

# -----------------------------------
# Third-Party Imports
# -----------------------------------
import requests
import pandas as pd
import tldextract
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TimeRemainingColumn, TimeElapsedColumn, SpinnerColumn, TextColumn
from rich.logging import RichHandler
from rich.text import Text

# -----------------------------------
# Typing
# -----------------------------------
from typing import Optional, Dict, Any, Tuple, List

VT_BASE = "https://www.virustotal.com/api/v3"

# Input column positions (0-indexed): C=2 E=4
IOC_COL_INDEX = 2
TYPE_COL_INDEX = 4

# Map free-form type labels in column E -> normalized types (single “type” column only)
TYPE_NORMALIZATION = {
    "DOMAIN": "domain",
    "URL": "url",
    "URI": "url",
    "IPV4": "ip",   # normalize to 'ip'
    "IP": "ip",
    "MD5": "file",
    "SHA1": "file",
    "SHA256": "file",
    "FILE": "file",
}

# -----------------------------------
# Regex Helpers
# -----------------------------------
HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
URL_RE = re.compile(
    r"^(?:https?://)"            # require scheme
    r"(?:[^\s/@]+@)?"            # optional userinfo
    r"(?:[A-Za-z0-9.-]+|\[[A-Fa-f0-9:]+\])"  # hostname or IPv6 literal
    r"(?::\d{1,5})?"             # optional port
    r"(?:/[^\s]*)?$"             # optional path/query/fragment
)


class UsageTracker:
    """
    Tracks API usage persistently in a local JSON file.
    - Persists daily and monthly counts by date/month key
    - Provides simple estimates for hitting caps
    """

    def __init__(self, state_file: str, daily_cap: int, monthly_cap: int):
        self.state_file = state_file
        self.daily_cap = daily_cap
        self.monthly_cap = monthly_cap
        self.state: Dict[str, Any] = self._load_state()
        # Ensure the state file exists on disk immediately
        self._save_state()

    def _load_state(self) -> Dict[str, Any]:
        try:
            if os.path.isfile(self.state_file):
                with open(self.state_file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    if isinstance(data, dict):
                        return data
        except Exception:
            pass
        return {}

    def _save_state(self) -> None:
        try:
            with open(self.state_file, "w", encoding="utf-8") as fh:
                json.dump(self.state, fh, indent=2, sort_keys=True)
        except Exception:
            pass

    @staticmethod
    def _day_key(d: date) -> str:
        return d.isoformat()  # YYYY-MM-DD

    @staticmethod
    def _month_key(d: date) -> str:
        return f"{d.year:04d}-{d.month:02d}"  # YYYY-MM

    def get_today_counts(self) -> int:
        key = self._day_key(date.today())
        return int(self.state.get("daily", {}).get(key, 0))

    def get_month_counts(self) -> int:
        key = self._month_key(date.today())
        return int(self.state.get("monthly", {}).get(key, 0))

    def bump(self, n: int = 1) -> None:
        today = date.today()
        day_key = self._day_key(today)
        month_key = self._month_key(today)

        self.state.setdefault("daily", {})
        self.state.setdefault("monthly", {})
        self.state["daily"][day_key] = int(self.state["daily"].get(day_key, 0)) + n
        self.state["monthly"][month_key] = int(self.state["monthly"].get(month_key, 0)) + n
        self._save_state()

    def remaining_today(self) -> int:
        return max(0, self.daily_cap - self.get_today_counts())

    def remaining_month(self) -> int:
        return max(0, self.monthly_cap - self.get_month_counts())

    def will_exceed_caps(self, required_calls: int) -> Tuple[bool, bool]:
        exceed_daily = required_calls > self.remaining_today()
        exceed_month = required_calls > self.remaining_month()
        return exceed_daily, exceed_month

    @staticmethod
    def estimate_minutes(required_calls: int, rate_per_min: int) -> float:
        if rate_per_min <= 0:
            return float("inf")
        return required_calls / float(rate_per_min)

def vt_url_id(url: str) -> str:
    """
    VirusTotal's GET /urls/{id} accepts an identifier that may be the base64url
    of the original URL (WITHOUT '=' padding). See VT docs.
    """
    b64 = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return b64.rstrip("=")

def norm_input_type(t: Optional[str]) -> Optional[str]:
    """Normalize free-form IOC type labels (from column E)."""
    if t is None:
        return None
    return TYPE_NORMALIZATION.get(str(t).strip().upper())

def is_hash(s: str) -> bool:
    """Lightweight check: does the IOC *look* like a hash (md5/sha1/sha256)?"""
    return bool(HASH_RE.match(str(s).strip()))

def parse_domain_from_url(u: str) -> Optional[str]:
    """
    Given a fully qualified URL, derive the registered domain.
    Prefer tldextract.registered_domain; fall back to urllib if needed.
    """
    try:
        if not URL_RE.match(u):
            return None
        ext = tldextract.extract(u)
        if ext.registered_domain:
            return ext.registered_domain
        return urlparse(u).hostname
    except Exception:
        return None


def _column_selector_to_index(selector: Optional[Any], df: Optional[pd.DataFrame] = None, default_index: int = 0) -> int:
    """
    Convert a flexible column selector into a 0-based index.
    Accepts:
      - None: returns default_index
      - int: if >= 0, treated as 0-based index; if > 0 and df is None, use as-is
      - str: can be a column letter (e.g., 'C' => 2), a 1-based integer string (e.g., '3' => 2),
              or a DataFrame column name (case-insensitive exact match) if df is provided
    """
    if selector is None:
        return default_index

    # If already an int
    if isinstance(selector, int):
        return selector if selector >= 0 else default_index

    # If string, try multiple forms
    s = str(selector).strip()
    if not s:
        return default_index

    # Try letter(s): A=0, B=1, ... Z=25
    if s.isalpha():
        # Support single letter for simplicity
        s_up = s.upper()
        if len(s_up) == 1 and 'A' <= s_up <= 'Z':
            return ord(s_up) - ord('A')

    # Try integer-like string (1-based or 0-based). We will treat as 1-based if >=1
    try:
        val = int(s)
        if val >= 1:
            return val - 1
        elif val == 0:
            return 0
    except ValueError:
        pass

    # If df provided, try to find column by name case-insensitive
    if df is not None:
        lower_to_idx = {str(col).strip().lower(): i for i, col in enumerate(list(df.columns))}
        idx = lower_to_idx.get(s.lower())
        if idx is not None:
            return idx

    return default_index

class VTClient:
    def __init__(self, api_key: str, rate_per_min: int = 4, timeout: int = 30, usage_tracker: Optional["UsageTracker"] = None):
        if rate_per_min <= 0:
            raise ValueError("rate_per_min must be > 0")
        self.api_key = api_key
        self.interval = 60.0 / float(rate_per_min)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": self.api_key})
        self._next_earliest = 0.0
        self.usage_tracker = usage_tracker

    def _respect_rate(self):
        now = time.time()
        if now < self._next_earliest:
            time.sleep(self._next_earliest - now)
        self._next_earliest = time.time() + self.interval

    def _request(self, method: str, url: str, params: Optional[dict] = None) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        self._respect_rate()
        logging.getLogger("vt_enrich").debug(f"HTTP {method} {url} params={params}")
        if self.usage_tracker:
            self.usage_tracker.bump()
        resp = self.session.request(method, url, params=params, timeout=self.timeout)
        logging.getLogger("vt_enrich").debug(f"→ Status {resp.status_code}")

        # Honor 429 Retry-After if present
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            try:
                wait_s = int(retry_after) if retry_after else 15
            except ValueError:
                wait_s = 15
            time.sleep(max(1, wait_s))
            self._respect_rate()
            if self.usage_tracker:
                self.usage_tracker.bump()
            resp = self.session.request(method, url, params=params, timeout=self.timeout)
            logging.getLogger("vt_enrich").debug(f"(retry) → Status {resp.status_code}")

        try:
            data = resp.json()
        except Exception:
            data = {"error": f"Non-JSON response (HTTP {resp.status_code})"}

        return resp.status_code, data, dict(resp.headers)

    # -------- Object Endpoints (v3) -------- #
    def get_ip(self, ip: str):
        return self._request("GET", f"{VT_BASE}/ip_addresses/{ip}")

    def get_domain(self, d: str):
        return self._request("GET", f"{VT_BASE}/domains/{d}")

    def get_url(self, u: str):
        uid = vt_url_id(u)
        return self._request("GET", f"{VT_BASE}/urls/{uid}")

    def get_file(self, h: str):
        return self._request("GET", f"{VT_BASE}/files/{h}")

    # -------- Relationships -------- #
    def get_relationships(self, obj: str, ident: str, rel: str, limit: int = 10):
        """
        Retrieve related objects via relationships API, e.g.:
          - files/{id}/relationships/contacted_domains
          - domains/{domain}/relationships/resolutions
          - ip_addresses/{ip}/relationships/resolutions
        """
        return self._request(
            "GET",
            f"{VT_BASE}/{obj}/{ident}/relationships/{rel}",
            params={"limit": limit},
        )

def extract_common_fields(ioc: str, ioc_type: str, status: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize VT v3 payload into vt_* columns for consistent downstream handling.
    """
    out: Dict[str, Any] = {
        "vt_http_status": status,
        "vt_permalink": None,
        "vt_reputation": None,
        "vt_last_analysis_date": None,
        "vt_stats_malicious": None,
        "vt_stats_suspicious": None,
        "vt_stats_harmless": None,
        "vt_tags": None,
        "vt_categories": None,
        "vt_first_submission_date": None,
        "vt_last_modification_date": None,
        "vt_error": None,
        "vt_raw_id": None,
        "vt_raw_type": None,
    }

    # Simple error passthrough
    if "error" in payload and not isinstance(payload["error"], dict):
        out["vt_error"] = str(payload["error"])
        return out

    data = payload.get("data")
    if not data:
        out["vt_error"] = (
            payload.get("error", {}).get("message")
            if isinstance(payload.get("error"), dict)
            else "No Data"
        )
        return out

    attrs = data.get("attributes", {}) or {}

    out["vt_raw_id"] = data.get("id")
    out["vt_raw_type"] = data.get("type")

    # Common attributes
    out["vt_reputation"] = attrs.get("reputation")
    out["vt_last_analysis_date"] = attrs.get("last_analysis_date")

    stats = attrs.get("last_analysis_stats", {}) or {}
    out["vt_stats_malicious"] = stats.get("malicious")
    out["vt_stats_suspicious"] = stats.get("suspicious")
    out["vt_stats_harmless"] = stats.get("harmless")

    out["vt_tags"] = ",".join(attrs.get("tags", [])) if attrs.get("tags") else None

    cats = attrs.get("categories")
    if isinstance(cats, dict):
        out["vt_categories"] = ",".join(sorted(set(cats.values())))
    elif isinstance(cats, list):
        out["vt_categories"] = ",".join(sorted(set(cats)))

    out["vt_first_submission_date"] = attrs.get("first_submission_date") or attrs.get("first_seen_itw_date")
    out["vt_last_modification_date"] = attrs.get("last_modification_date")

    # Permalinks (GUI)
    if ioc_type == "ip":
        out["vt_permalink"] = f"https://www.virustotal.com/gui/ip-address/{ioc}"
    elif ioc_type == "domain":
        out["vt_permalink"] = f"https://www.virustotal.com/gui/domain/{ioc}"
    elif ioc_type == "url":
        out["vt_permalink"] = f"https://www.virustotal.com/gui/url/{vt_url_id(ioc)}"
    elif ioc_type == "file":
        sha256 = attrs.get("sha256") or data.get("id")
        if sha256:
            out["vt_permalink"] = f"https://www.virustotal.com/gui/file/{sha256}"

    return out

def file_hash_triplet_from_attrs(attrs: Dict[str, Any]) -> Dict[str, Optional[str]]:
    return {
        "vt_md5": attrs.get("md5"),
        "vt_sha1": attrs.get("sha1"),
        "vt_sha256": attrs.get("sha256"),
    }

def enrich_row(
    ioc: str,
    in_type_label: str,
    client: VTClient,
    relationships: bool = False,
    rel_limit: int = 5
) -> Dict[str, Any]:
    """
    Enrich a single row using the VT client (no per-hash input columns expected).

    Returns a flat dict containing:
      - normalized_type
      - derived_domain_from_url (if URL)
      - additional_iocs (JSON list of {type, value, source})
      - vt_* summary fields
      - vt_md5/vt_sha1/vt_sha256 (for file objects when available)
    """
    t_norm = norm_input_type(in_type_label)

    result: Dict[str, Any] = {
        "normalized_type": t_norm,
        "derived_domain_from_url": None,
        "additional_iocs": json.dumps([]),
        "vt_md5": None, "vt_sha1": None, "vt_sha256": None,
    }

    # Local derivation for URL -> domain (cheap)
    if t_norm == "url":
        dom = parse_domain_from_url(ioc)
        if dom:
            result["derived_domain_from_url"] = dom
            result["additional_iocs"] = json.dumps(
                [{"type": "domain", "value": dom, "source": "derived_from_url"}]
            )

    if t_norm == "ip":
        status, payload, _ = client.get_ip(ioc)
        result.update(extract_common_fields(ioc, "ip", status, payload))

        # Optional: IP <-> domain resolutions
        if relationships and status == 200 and result.get("vt_raw_id"):
            rstatus, rpayload, _ = client.get_relationships("ip_addresses", ioc, "resolutions", limit=rel_limit)
            doms = []
            for d in (rpayload.get("data") or []):
                dom = d.get("attributes", {}).get("host_name")
                if dom:
                    doms.append({"type": "domain", "value": dom, "source": "vt_resolutions"})
            if doms:
                result["additional_iocs"] = json.dumps(doms)

    elif t_norm == "domain":
        status, payload, _ = client.get_domain(ioc)
        result.update(extract_common_fields(ioc, "domain", status, payload))

        if relationships and status == 200 and result.get("vt_raw_id"):
            rstatus, rpayload, _ = client.get_relationships("domains", ioc, "resolutions", limit=rel_limit)
            ips = []
            for d in (rpayload.get("data") or []):
                ip = d.get("attributes", {}).get("ip_address")
                if ip:
                    ips.append({"type": "ip", "value": ip, "source": "vt_resolutions"})
            if ips:
                result["additional_iocs"] = json.dumps(ips)

    elif t_norm == "url":
        status, payload, _ = client.get_url(ioc)
        result.update(extract_common_fields(ioc, "url", status, payload))
        # (Relationships for URLs omitted on free tiers due to cost)

    elif t_norm == "file" or (t_norm is None and is_hash(ioc)):
        # Treat hash-looking IOCs as 'file' for resiliency if column E was missing/incorrect
        status, payload, _ = client.get_file(ioc)
        result.update(extract_common_fields(ioc, "file", status, payload))

        attrs = (payload.get("data") or {}).get("attributes", {}) if isinstance(payload, dict) else {}
        result.update(file_hash_triplet_from_attrs(attrs))

        if relationships and status == 200 and result.get("vt_raw_id"):
            file_id = result["vt_raw_id"]
            collected: List[Dict[str, str]] = []

            # Contacted Domains
            rstatus, rpayload, _ = client.get_relationships("files", file_id, "contacted_domains", limit=rel_limit)
            for d in (rpayload.get("data") or []):
                val = d.get("id")
                if val:
                    collected.append({"type": "domain", "value": val, "source": "vt_contacted_domains"})

            # Contacted IPs
            rstatus, rpayload, _ = client.get_relationships("files", file_id, "contacted_ips", limit=rel_limit)
            for d in (rpayload.get("data") or []):
                val = d.get("id")
                if val:
                    collected.append({"type": "ip", "value": val, "source": "vt_contacted_ips"})

            if collected:
                result["additional_iocs"] = json.dumps(collected)

    else:
        # Unknown/unsupported type and not a hash
        result.update({
            "vt_http_status": None,
            "vt_error": "Unrecognized or unsupported IOC type.",
        })

    return result

# -----------------------------
# CSV pipeline (single IOC type col E; no per-hash input columns)
# -----------------------------
def process_csv(
    input_csv_path: str,
    output_csv_path: str,
    rate_per_min: int = 4,
    timeout: int = 30,
    relationships: bool = False,
    relationships_limit: int = 5,
    usage_tracker: Optional["UsageTracker"] = None,
    ioc_col_index: Optional[int] = None,
    type_col_index: Optional[int] = None,
    console: Optional[Console] = None,
    print_each_row: bool = True,
) -> pd.DataFrame:
    """
    Pipeline:
      1) Read CSV (preserve strings).
      2) Extract IOC (col C) and IOC type (col E) by POSITION → indices 2 and 4.
      3) Init VT client.
      4) Row-wise enrich via enrich_row(...).
      5) Merge results to original DF.
      6) Expose VT-derived hashes (no matching against input; no input SHA cols assumed).
      7) Write CSV and return DF.
    """
    # --- API key check ---
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise RuntimeError("VIRUSTOTAL_API_KEY is not set in the environment.")

    # --- Load CSV ---
    df = pd.read_csv(input_csv_path, dtype=str, keep_default_na=False)

    # Resolve which columns to use
    resolved_ioc_idx = ioc_col_index if ioc_col_index is not None else IOC_COL_INDEX
    resolved_type_idx = type_col_index if type_col_index is not None else TYPE_COL_INDEX

    if df.shape[1] <= max(resolved_ioc_idx, resolved_type_idx):
        raise ValueError(
            f"Input file must have at least {max(resolved_ioc_idx, resolved_type_idx)+1} columns by position. Found {df.shape[1]}."
        )

    # --- Extract IOC and Type ---
    df["ioc"] = df.iloc[:, resolved_ioc_idx].astype(str).str.strip()
    df["ioc_type_input"] = df.iloc[:, resolved_type_idx].astype(str).str.strip()

    # --- VT client (free-tier friendly pacing) ---
    client = VTClient(api_key=api_key, rate_per_min=rate_per_min, timeout=timeout, usage_tracker=usage_tracker)

    # --- Enrich (paced loop with progress) ---
    enrich_records: List[Dict[str, Any]] = []
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        transient=True,
    )
    logger = logging.getLogger("vt_enrich")
    with progress:
        task_id = progress.add_task("Enriching rows", total=len(df))
        for _, row in df.iterrows():
            info = enrich_row(
                ioc=row["ioc"],
                in_type_label=row["ioc_type_input"],
                client=client,
                relationships=relationships,
                rel_limit=relationships_limit
            )
            enrich_records.append(info)
            progress.advance(task_id)
            if info.get("vt_error"):
                logger.warning(f"IOC '{row['ioc']}' ({row['ioc_type_input']}): {info.get('vt_error')}")
            if print_each_row and console is not None:
                norm = info.get("normalized_type") or "-"
                status = info.get("vt_http_status")
                ok = (status == 200) and (info.get("vt_error") in (None, ""))
                icon = "[green]✔[/green]" if ok else "[red]✖[/red]"
                console.print(f"{icon} [bold]{row['ioc']}[/bold] [dim]({norm})[/dim] [cyan]{status if status is not None else ''}[/cyan]")

    enrich_df = pd.DataFrame(enrich_records)

    # --- Merge and expose hashes (VT is authoritative) ---
    out = pd.concat([df, enrich_df], axis=1)
    for col in ("vt_md5", "vt_sha1", "vt_sha256"):
        if col not in out.columns:
            out[col] = ""
        else:
            out[col] = out[col].fillna("")

    # Convenience mirrors (optional)
    out["sha1_from_vt"] = out["vt_sha1"].where(out["vt_sha1"].ne(""), None)
    out["sha256_from_vt"] = out["vt_sha256"].where(out["vt_sha256"].ne(""), None)

    # --- Persist ---
    out.to_csv(output_csv_path, index=False, quoting=csv.QUOTE_MINIMAL)
    print(f"[+] Enriched CSV written to: {output_csv_path}")
    return out


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Enrich a CSV with VirusTotal data. Assumes IOC in column C (index 2) and IOC type in column E (index 4)."
        )
    )
    parser.add_argument(
        "--config",
        dest="config_path",
        help=(
            "Path to a JSON config file with defaults (api_key, rate_per_min, timeout, relationships, relationships_limit).\n"
            "If not provided, the tool will look for vt_config.local.json then vt_config.json in the current directory."
        ),
    )
    parser.add_argument(
        "--ioc-col",
        dest="ioc_col",
        default=None,
        help=(
            "IOC column selector: accepts 0-based index (e.g., 2), 1-based index as string (e.g., '3'), "
            "column letter (e.g., 'C'), or header name (exact match, case-insensitive). If omitted, defaults to column C."
        ),
    )
    parser.add_argument(
        "--type-col",
        dest="type_col",
        default=None,
        help=(
            "IOC type column selector: accepts 0-based index, 1-based index string, column letter, or header name. "
            "If omitted, defaults to column E."
        ),
    )
    parser.add_argument(
        "input_csv",
        help="Path to input CSV file",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_csv",
        help="Path to write enriched CSV (default: <input_basename>.enriched.csv)",
    )
    parser.add_argument(
        "--rate",
        dest="rate_per_min",
        type=int,
        default=None,
        help="API request pace in requests per minute (default: 4)",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=None,
        help="HTTP request timeout in seconds (default: 30)",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--relationships",
        dest="relationships",
        action="store_true",
        help="Also fetch selected relationships (resolutions/contacted IOCs). May increase API usage.",
    )
    group.add_argument(
        "--no-relationships",
        dest="relationships",
        action="store_false",
        help="Disable fetching relationships.",
    )
    parser.set_defaults(relationships=None)
    parser.add_argument(
        "--rel-limit",
        dest="relationships_limit",
        type=int,
        default=None,
        help="Max related objects to fetch per relationship (default: 5)",
    )
    parser.add_argument(
        "--daily-cap",
        dest="daily_cap",
        type=int,
        default=None,
        help="Daily request quota for estimation/tracking (default: 500)",
    )
    parser.add_argument(
        "--monthly-cap",
        dest="monthly_cap",
        type=int,
        default=None,
        help="Monthly request quota for estimation/tracking (default: 15500)",
    )
    parser.add_argument(
        "--usage-state",
        dest="usage_state_file",
        default=None,
        help="Path to a local JSON file used to persist usage counts (default: ./.vt_usage.json)",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        default=None,
        help="Base directory for outputs. Files are saved under <output_dir>/<YYYY-MM-DD>/. Default: ./out",
    )
    parser.add_argument(
        "--logs-dir",
        dest="logs_dir",
        default=None,
        help="Base directory for logs. Logs are saved under <logs_dir>/<YYYY-MM-DD>/. Default: ./logs",
    )
    parser.add_argument(
        "--no-row-print",
        dest="row_print",
        action="store_false",
        help="Disable per-row pretty output",
    )
    parser.set_defaults(row_print=True)
    parser.add_argument(
        "--api-key",
        dest="api_key",
        help=(
            "VirusTotal API key. If omitted, the VIRUSTOTAL_API_KEY environment variable must be set."
        ),
    )
    return parser


def _load_config(path_from_cli: Optional[str]) -> Dict[str, Any]:
    """Load configuration from JSON. Preference: CLI path > ./vt_config.local.json > ./vt_config.json.

    Returns an empty dict if no config file is found or load fails.
    """
    candidate_paths: List[str] = []
    if path_from_cli:
        candidate_paths.append(path_from_cli)
    # Current working directory fallbacks
    candidate_paths.append(os.path.abspath("vt_config.local.json"))
    candidate_paths.append(os.path.abspath("vt_config.json"))

    for p in candidate_paths:
        try:
            if os.path.isfile(p):
                with open(p, "r", encoding="utf-8") as fh:
                    return json.load(fh) or {}
        except Exception:
            # Ignore malformed config and fall through to empty
            return {}
    return {}


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Prepare console for pretty output
    console = Console()

    # Load config (optional)
    cfg = _load_config(args.config_path)

    # Resolve API key precedence: CLI > ENV > CONFIG
    if args.api_key:
        os.environ["VIRUSTOTAL_API_KEY"] = args.api_key
    elif not os.getenv("VIRUSTOTAL_API_KEY"):
        api_key_from_cfg = cfg.get("api_key") if isinstance(cfg, dict) else None
        if api_key_from_cfg:
            os.environ["VIRUSTOTAL_API_KEY"] = str(api_key_from_cfg)

    input_csv_path = args.input_csv
    output_csv_path = args.output_csv  # may be None; if None we will write into out/<date>/ with a session-based name

    # Effective options with precedence: CLI (if provided) -> CONFIG -> defaults
    effective_rate = args.rate_per_min if args.rate_per_min is not None else int(cfg.get("rate_per_min", 4))
    effective_timeout = args.timeout if args.timeout is not None else int(cfg.get("timeout", 30))
    if args.relationships is None:
        effective_relationships = bool(cfg.get("relationships", False))
    else:
        effective_relationships = args.relationships
    effective_rel_limit = args.relationships_limit if args.relationships_limit is not None else int(cfg.get("relationships_limit", 5))

    effective_daily_cap = args.daily_cap if args.daily_cap is not None else int(cfg.get("daily_cap", 500))
    effective_monthly_cap = args.monthly_cap if args.monthly_cap is not None else int(cfg.get("monthly_cap", 15500))
    effective_usage_state_file = args.usage_state_file if args.usage_state_file is not None else str(cfg.get("usage_state_file", ".vt_usage.json"))

    # Output and logs directories
    effective_output_dir = args.output_dir if args.output_dir is not None else str(cfg.get("output_dir", "out"))
    effective_logs_dir = args.logs_dir if args.logs_dir is not None else str(cfg.get("logs_dir", "logs"))

    # Session id for unique file naming
    session_id = datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{uuid.uuid4().hex[:6]}"
    daily_key = date.today().isoformat()
    daily_output_dir = os.path.abspath(os.path.join(effective_output_dir, daily_key))
    daily_logs_dir = os.path.abspath(os.path.join(effective_logs_dir, daily_key))
    os.makedirs(daily_output_dir, exist_ok=True)
    os.makedirs(daily_logs_dir, exist_ok=True)

    # Configure logging (Rich console + file)
    log_path = os.path.join(daily_logs_dir, f"vt_enrich_{session_id}.log")
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    # Rich console handler
    rich_handler = RichHandler(rich_tracebacks=False, markup=True, console=console)
    rich_handler.setLevel(logging.INFO)
    rich_handler.setFormatter(logging.Formatter("%(message)s"))
    # File handler with detailed format
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    # Reset handlers to avoid duplication on repeated runs in same interpreter
    root_logger.handlers = []
    root_logger.addHandler(rich_handler)
    root_logger.addHandler(file_handler)
    logger = logging.getLogger("vt_enrich")

    usage_tracker = UsageTracker(
        state_file=os.path.abspath(effective_usage_state_file),
        daily_cap=effective_daily_cap,
        monthly_cap=effective_monthly_cap,
    )

    # --- Preflight estimation & quota checks ---
    try:
        df_preview = pd.read_csv(input_csv_path, dtype=str, keep_default_na=False)
        # Resolve column indices with flexibility (CLI > CFG > defaults)
        # Prefer explicit CLI > config; otherwise try header names 'ioc'/'type' before falling back to defaults
        ioc_selector = args.ioc_col if args.ioc_col is not None else (cfg.get("ioc_col") if cfg.get("ioc_col") is not None else "ioc")
        type_selector = args.type_col if args.type_col is not None else (cfg.get("type_col") if cfg.get("type_col") is not None else "type")

        ioc_col_index = _column_selector_to_index(
            ioc_selector,
            df=df_preview,
            default_index=IOC_COL_INDEX,
        )
        type_col_index = _column_selector_to_index(
            type_selector,
            df=df_preview,
            default_index=TYPE_COL_INDEX,
        )

        if df_preview.shape[1] <= max(ioc_col_index, type_col_index):
            raise ValueError(
                f"Input file must have at least {max(ioc_col_index, type_col_index)+1} columns by position. Found {df_preview.shape[1]}."
            )
        num_rows = len(df_preview)
        minutes_estimate = UsageTracker.estimate_minutes(num_rows, effective_rate)
        est_str = f"~{int(minutes_estimate)} minutes" if minutes_estimate < 60 else f"~{minutes_estimate/60:.1f} hours"

        remaining_today = usage_tracker.remaining_today()
        remaining_month = usage_tracker.remaining_month()
        exceed_daily, exceed_month = usage_tracker.will_exceed_caps(num_rows)

        info_table = Table(title="Preflight Estimate", show_edge=True, header_style="bold cyan")
        info_table.add_column("Metric", style="bold")
        info_table.add_column("Value")
        info_table.add_row("Rows to process", str(num_rows))
        info_table.add_row("Rate (per min)", str(effective_rate))
        info_table.add_row("Estimated time", est_str)
        info_table.add_row("Remaining today", f"{remaining_today} / {effective_daily_cap}")
        info_table.add_row("Remaining month", f"{remaining_month} / {effective_monthly_cap}")
        warnings = []
        if exceed_daily:
            warnings.append("Exceeds daily cap")
        if exceed_month:
            warnings.append("Exceeds monthly cap")
        if warnings:
            info_table.add_row("Warnings", ", ".join(warnings))
        banner = Panel(
            Text.from_markup(
                "[bold cyan]VTEnrich[/bold cyan]\n"
                "[white]Built by [bold]Chris Cooley[/bold][/white]"
            ),
            title="Welcome",
            border_style="magenta",
        )
        console.print(banner)
        console.print(Panel(info_table, title=f"Session {session_id}", border_style="green"))
    except Exception as preflight_exc:
        console.print(f"[yellow][i][/yellow] Preflight estimation skipped: {preflight_exc}")

    try:
        # Decide output path: if user provided -o and it looks like a .csv file, honor it.
        # If -o provided and is a directory, write inside it.
        # Otherwise, write into daily_output_dir with a unique session-based name.
        final_output_path = output_csv_path
        input_base = os.path.splitext(os.path.basename(input_csv_path))[0]
        if final_output_path:
            if os.path.isdir(final_output_path):
                final_output_path = os.path.join(final_output_path, f"{input_base}.{session_id}.enriched.csv")
            elif not final_output_path.lower().endswith(".csv"):
                # Treat as directory path
                os.makedirs(final_output_path, exist_ok=True)
                final_output_path = os.path.join(final_output_path, f"{input_base}.{session_id}.enriched.csv")
            else:
                # Ensure directory exists
                os.makedirs(os.path.dirname(os.path.abspath(final_output_path)) or ".", exist_ok=True)
        else:
            final_output_path = os.path.join(daily_output_dir, f"{input_base}.{session_id}.enriched.csv")

        logger.info(f"Writing output to: {final_output_path}")
        logger.info(f"Session log: {log_path}")

        df = process_csv(
            input_csv_path=input_csv_path,
            output_csv_path=final_output_path,
            rate_per_min=effective_rate,
            timeout=effective_timeout,
            relationships=effective_relationships,
            relationships_limit=effective_rel_limit,
            usage_tracker=usage_tracker,
            ioc_col_index=ioc_col_index,
            type_col_index=type_col_index,
            console=console,
            print_each_row=args.row_print,
        )
        console.print(f"[bold green][+] Rows processed:[/bold green] {len(df)}")
        console.print(f"[bold]Output:[/bold] {final_output_path}")
        console.print(f"[bold]Log:[/bold] {log_path}")
        return 0
    except Exception as exc:
        console.print(f"[red][!][/red] Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
