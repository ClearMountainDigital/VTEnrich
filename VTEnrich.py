# -----------------------------------
# Standard Library Imports
# -----------------------------------
import argparse
import os
import re
import csv
import json
import time
import hashlib
import tempfile
from datetime import datetime, date, timezone
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
URLSCAN_BASE = "https://urlscan.io/api/v1"
USER_AGENT = "VTEnrich/2.0 (+https://github.com/)"

# Input column positions (0-indexed): C=2 E=4
IOC_COL_INDEX = 2
TYPE_COL_INDEX = 4

# Action keys used by UsageTracker and per-action self-pacing
ACTION_VT = "vt"
ACTION_URLSCAN_SEARCH = "urlscan_search"
ACTION_URLSCAN_SUBMIT = "urlscan_submit"
ACTION_URLSCAN_RETRIEVE = "urlscan_retrieve"

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
    Tracks API usage persistently in a local JSON file, scoped per provider
    action (e.g. 'vt', 'urlscan_search', 'urlscan_submit', 'urlscan_retrieve').

    State schema (new):
        {
          "actions": {
            "<action>": {
              "daily":   {"YYYY-MM-DD": int},
              "monthly": {"YYYY-MM": int}
            }, ...
          },
          "daily":   {"YYYY-MM-DD": int},  // legacy mirror of 'vt' for backward compat
          "monthly": {"YYYY-MM": int}      // legacy mirror of 'vt'
        }

    Legacy files (without 'actions') are auto-migrated on load by treating
    the top-level daily/monthly counts as the 'vt' action.
    """

    def __init__(self, state_file: str, caps: Dict[str, Dict[str, int]]):
        # caps: {"<action>": {"daily": int, "monthly": int, "hourly": int?, "minute": int?}}
        self.state_file = state_file
        self.caps = caps or {}
        self.state: Dict[str, Any] = self._load_state()
        self._migrate_legacy()
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
            # Atomic write
            dir_ = os.path.dirname(os.path.abspath(self.state_file)) or "."
            os.makedirs(dir_, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".vtusage_", suffix=".tmp", dir=dir_)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(self.state, fh, indent=2, sort_keys=True)
                os.replace(tmp, self.state_file)
            finally:
                if os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
        except Exception:
            pass

    def _migrate_legacy(self) -> None:
        """If the state has top-level daily/monthly but no actions['vt'], copy them."""
        if "actions" not in self.state:
            self.state["actions"] = {}
        legacy_daily = self.state.get("daily")
        legacy_monthly = self.state.get("monthly")
        if (legacy_daily or legacy_monthly) and ACTION_VT not in self.state["actions"]:
            self.state["actions"][ACTION_VT] = {
                "daily": dict(legacy_daily or {}),
                "monthly": dict(legacy_monthly or {}),
            }

    @staticmethod
    def _day_key(d: date) -> str:
        return d.isoformat()  # YYYY-MM-DD

    @staticmethod
    def _month_key(d: date) -> str:
        return f"{d.year:04d}-{d.month:02d}"  # YYYY-MM

    def _action_block(self, action: str) -> Dict[str, Dict[str, int]]:
        actions = self.state.setdefault("actions", {})
        return actions.setdefault(action, {"daily": {}, "monthly": {}})

    def get_count(self, action: str, window: str = "daily") -> int:
        block = self._action_block(action)
        if window == "daily":
            return int(block.get("daily", {}).get(self._day_key(date.today()), 0))
        if window == "monthly":
            return int(block.get("monthly", {}).get(self._month_key(date.today()), 0))
        return 0

    def remaining(self, action: str, window: str = "daily") -> int:
        cap = self.caps.get(action, {}).get(window)
        if cap is None:
            return 10**9  # effectively unbounded for windows we don't track
        return max(0, int(cap) - self.get_count(action, window))

    def bump(self, action: str = ACTION_VT, n: int = 1) -> None:
        today = date.today()
        day_key = self._day_key(today)
        month_key = self._month_key(today)
        block = self._action_block(action)
        block.setdefault("daily", {})
        block.setdefault("monthly", {})
        block["daily"][day_key] = int(block["daily"].get(day_key, 0)) + n
        block["monthly"][month_key] = int(block["monthly"].get(month_key, 0)) + n
        # Mirror legacy top-level counters for VT (backward compat)
        if action == ACTION_VT:
            self.state.setdefault("daily", {})
            self.state.setdefault("monthly", {})
            self.state["daily"][day_key] = int(self.state["daily"].get(day_key, 0)) + n
            self.state["monthly"][month_key] = int(self.state["monthly"].get(month_key, 0)) + n
        self._save_state()

    # --- Legacy accessors retained for callers that still use them ---
    def get_today_counts(self) -> int:
        return self.get_count(ACTION_VT, "daily")

    def get_month_counts(self) -> int:
        return self.get_count(ACTION_VT, "monthly")

    def remaining_today(self) -> int:
        return self.remaining(ACTION_VT, "daily")

    def remaining_month(self) -> int:
        return self.remaining(ACTION_VT, "monthly")

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
        self.session.headers.update({"x-apikey": self.api_key, "User-Agent": USER_AGENT})
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
            self.usage_tracker.bump(action=ACTION_VT)
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
                self.usage_tracker.bump(action=ACTION_VT)
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

class URLScanClient:
    """
    URLScan.io API client with per-action self-pacing driven by the
    X-Rate-Limit-* response headers.

    Actions:
      - 'search'   : GET /search/?q=page.domain:"<d>"
      - 'submit'   : POST /scan/  (default visibility = unlisted)
      - 'retrieve' : GET /result/{uuid}/

    Per URLScan docs, only HTTP 200 responses count against quota; we
    only bump the usage tracker on success.
    """

    def __init__(self, api_key: str, timeout: int = 30, usage_tracker: Optional["UsageTracker"] = None):
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"API-Key": self.api_key, "User-Agent": USER_AGENT})
        self.usage_tracker = usage_tracker
        self._next_earliest: Dict[str, float] = {
            ACTION_URLSCAN_SEARCH: 0.0,
            ACTION_URLSCAN_SUBMIT: 0.0,
            ACTION_URLSCAN_RETRIEVE: 0.0,
        }

    def _respect_action(self, action: str) -> None:
        ne = self._next_earliest.get(action, 0.0)
        now = time.time()
        if now < ne:
            time.sleep(ne - now)

    def _apply_rate_headers(self, action: str, resp: requests.Response) -> None:
        """Spread remaining calls across the reset window per response headers."""
        try:
            remaining = int(resp.headers.get("X-Rate-Limit-Remaining", "9999"))
            reset_after = int(resp.headers.get("X-Rate-Limit-Reset-After", "0"))
        except (TypeError, ValueError):
            return
        now = time.time()
        if remaining <= 0 and reset_after > 0:
            self._next_earliest[action] = now + reset_after + 1
        elif reset_after > 0 and remaining < 10:
            interval = reset_after / float(remaining + 1)
            self._next_earliest[action] = now + interval

    def _request(self, action: str, method: str, url: str, **kwargs) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        self._respect_action(action)
        logger = logging.getLogger("vt_enrich")
        logger.debug(f"URLSCAN {method} {url} action={action}")
        try:
            resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.RequestException as exc:
            logger.debug(f"URLSCAN error: {exc}")
            return 0, {"error": f"Request failed: {exc}"}, {}

        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            try:
                wait_s = int(retry_after) if retry_after else 30
            except ValueError:
                wait_s = 30
            logger.debug(f"URLSCAN 429 — sleeping {wait_s}s")
            time.sleep(max(5, wait_s))
            try:
                resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                return 0, {"error": f"Request failed (retry): {exc}"}, {}

        self._apply_rate_headers(action, resp)
        if resp.status_code == 200 and self.usage_tracker:
            self.usage_tracker.bump(action=action)

        try:
            data = resp.json()
        except Exception:
            data = {"error": f"Non-JSON response (HTTP {resp.status_code})"}
        return resp.status_code, data, dict(resp.headers)

    def search_domain(self, domain: str, size: int = 10):
        params = {"q": f'page.domain:"{domain}"', "size": size}
        return self._request(ACTION_URLSCAN_SEARCH, "GET", f"{URLSCAN_BASE}/search/", params=params)

    def submit_url(self, url: str, visibility: str = "unlisted"):
        body = {"url": url, "visibility": visibility, "tags": ["vtenrich"]}
        return self._request(ACTION_URLSCAN_SUBMIT, "POST", f"{URLSCAN_BASE}/scan/", json=body)

    def get_result(self, scan_id: str):
        return self._request(ACTION_URLSCAN_RETRIEVE, "GET", f"{URLSCAN_BASE}/result/{scan_id}/")


def _parse_iso8601(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        # Handle trailing Z
        s = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return None


def urlscan_verdict_from_search(payload: Dict[str, Any], stale_days: int) -> Optional[Dict[str, Any]]:
    """
    Pick the freshest result from URLScan search with a usable verdict.

    "Usable" = at least one of: score != 0, non-empty categories, or non-empty brands.
    Returns None if no result is fresh-enough or none carry a verdict.
    """
    results = payload.get("results") or []
    if not results:
        return None
    now = datetime.now(timezone.utc)
    cutoff = stale_days * 86400.0

    # Results are typically newest-first, but sort to be safe
    def _ts(r):
        return _parse_iso8601((r.get("task") or {}).get("time")) or datetime.min.replace(tzinfo=timezone.utc)

    results = sorted(results, key=_ts, reverse=True)

    for r in results:
        scan_time = _parse_iso8601((r.get("task") or {}).get("time"))
        if scan_time is None:
            continue
        age_s = (now - scan_time).total_seconds()
        if age_s > cutoff:
            continue
        verdicts = (r.get("verdicts") or {}).get("urlscan") or {}
        score = verdicts.get("score", 0) or 0
        categories = verdicts.get("categories") or []
        brands = verdicts.get("brands") or []
        if score == 0 and not categories and not brands:
            continue  # non-verdict, fall through
        return {
            "scan_id": (r.get("task") or {}).get("uuid"),
            "scan_time": scan_time.isoformat(),
            "score": int(score),
            "categories": categories,
            "brands": [b.get("name") for b in brands if isinstance(b, dict) and b.get("name")],
            "permalink": r.get("result"),
        }
    return None


def urlscan_verdict_from_result(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract verdict from a single /result/{uuid}/ payload.

    Returns None when the result carries no usable verdict (score == 0 AND
    empty categories AND empty brands). This mirrors urlscan_verdict_from_search
    and prevents a zero-score "no opinion" result from being mis-scored as
    malicious by compute_composite_verdict (which maps urlscan_score=0 to 50/100).
    """
    task = payload.get("task") or {}
    verdicts = (payload.get("verdicts") or {}).get("urlscan") or {}
    if not task and not verdicts:
        return None
    score = verdicts.get("score", 0) or 0
    categories = verdicts.get("categories") or []
    brands = verdicts.get("brands") or []
    if score == 0 and not categories and not brands:
        return None  # no opinion — caller treats as miss
    scan_time = _parse_iso8601(task.get("time"))
    return {
        "scan_id": task.get("uuid"),
        "scan_time": scan_time.isoformat() if scan_time else None,
        "score": int(score),
        "categories": categories,
        "brands": [b.get("name") for b in brands if isinstance(b, dict) and b.get("name")],
        "permalink": task.get("reportURL"),
    }


def _empty_urlscan_cols() -> Dict[str, Any]:
    return {
        "urlscan_score": None,
        "urlscan_categories": None,
        "urlscan_brands": None,
        "urlscan_scan_date": None,
        "urlscan_scan_id": None,
        "urlscan_permalink": None,
    }


def _urlscan_cols_from_verdict(v: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "urlscan_score": v.get("score"),
        "urlscan_categories": ",".join(v.get("categories") or []) or None,
        "urlscan_brands": ",".join(v.get("brands") or []) or None,
        "urlscan_scan_date": v.get("scan_time"),
        "urlscan_scan_id": v.get("scan_id"),
        "urlscan_permalink": v.get("permalink"),
    }


def compute_composite_verdict(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce maliciousness_score (0-100), verdict_source, verdict_summary.

    Source priority is implied by which columns are populated; verdict_source
    is set by the enricher when it commits a primary signal. We just compute
    the numeric score and summary here.

    Formula:
      - URLScan score present: maliciousness_score = (urlscan_score + 100) / 2
      - VT only (no URLScan): 100 * m / max(1, m + s + h + u)
        where m=malicious, s=suspicious, h=harmless, u=undetected
      - Neither: None
    """
    out: Dict[str, Any] = {"maliciousness_score": None, "verdict_summary": "unknown"}

    score = None
    if row.get("urlscan_score") is not None:
        try:
            us = int(row["urlscan_score"])
            # URLScan score=0 means "no opinion", not midway. Fall through to VT.
            if us != 0:
                score = (us + 100) / 2.0
        except (TypeError, ValueError):
            score = None
    if score is None:
        m = row.get("vt_stats_malicious") or 0
        s = row.get("vt_stats_suspicious") or 0
        h = row.get("vt_stats_harmless") or 0
        u = row.get("vt_stats_undetected") or 0
        try:
            total = int(m) + int(s) + int(h) + int(u)
            if total > 0:
                score = 100.0 * int(m) / total
        except (TypeError, ValueError):
            score = None

    if score is not None:
        out["maliciousness_score"] = round(float(score), 2)
        if score >= 50:
            out["verdict_summary"] = "malicious"
        elif score >= 20:
            out["verdict_summary"] = "suspicious"
        else:
            out["verdict_summary"] = "benign"
    return out


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
        "vt_stats_undetected": None,
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
    out["vt_stats_undetected"] = stats.get("undetected")

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

def _resolve_type(in_type_label: Optional[str], default_type: Optional[str], ioc: str) -> Optional[str]:
    t = norm_input_type(in_type_label)
    if t is None and default_type:
        t = norm_input_type(default_type) or (default_type if default_type in {"domain", "url", "ip", "file"} else None)
    if t is None and is_hash(ioc):
        t = "file"
    return t


def enrich_row_phase1(
    ioc: str,
    in_type_label: Optional[str],
    default_type: Optional[str] = None,
    vt_client: Optional[VTClient] = None,
    urlscan_client: Optional[URLScanClient] = None,
    urlscan_stale_days: int = 90,
    use_urlscan: bool = True,
    use_vt: bool = True,
    submit_missing: bool = True,
    urlscan_visibility: str = "unlisted",
    relationships: bool = False,
    rel_limit: int = 5,
) -> Dict[str, Any]:
    """
    Phase 1: look up a single row. For domain/url types, runs the chain:
        URLScan search -> VT fallback -> optional submit (queues scan_id).
    For ip/file: VT only (legacy behavior).

    Returns a dict containing all normalized columns. If submission was queued,
    `verdict_source` is 'urlscan_submit_pending' and `urlscan_scan_id` holds
    the queued UUID for phase 2 to resolve.
    """
    t_norm = _resolve_type(in_type_label, default_type, ioc)

    result: Dict[str, Any] = {
        "normalized_type": t_norm,
        "derived_domain_from_url": None,
        "additional_iocs": json.dumps([]),
        "vt_md5": None, "vt_sha1": None, "vt_sha256": None,
    }
    result.update(_empty_urlscan_cols())
    result["verdict_source"] = "none"
    result["maliciousness_score"] = None
    result["verdict_summary"] = "unknown"

    if t_norm == "url":
        dom = parse_domain_from_url(ioc)
        if dom:
            result["derived_domain_from_url"] = dom
            result["additional_iocs"] = json.dumps(
                [{"type": "domain", "value": dom, "source": "derived_from_url"}]
            )

    if t_norm in ("domain", "url"):
        verdict_locked = False

        # 1) URLScan search
        if use_urlscan and urlscan_client is not None:
            status, payload, _ = urlscan_client.search_domain(ioc)
            if status == 200:
                v = urlscan_verdict_from_search(payload, urlscan_stale_days)
                if v:
                    result.update(_urlscan_cols_from_verdict(v))
                    result["verdict_source"] = "urlscan_search"
                    verdict_locked = True

        # 2) VT fallback
        if not verdict_locked and use_vt and vt_client is not None:
            if t_norm == "domain":
                status, payload, _ = vt_client.get_domain(ioc)
                result.update(extract_common_fields(ioc, "domain", status, payload))
                if relationships and status == 200 and result.get("vt_raw_id"):
                    _rs, rp, _ = vt_client.get_relationships("domains", ioc, "resolutions", limit=rel_limit)
                    ips = [
                        {"type": "ip", "value": d.get("attributes", {}).get("ip_address"), "source": "vt_resolutions"}
                        for d in (rp.get("data") or []) if d.get("attributes", {}).get("ip_address")
                    ]
                    if ips:
                        result["additional_iocs"] = json.dumps(ips)
            else:  # url
                status, payload, _ = vt_client.get_url(ioc)
                result.update(extract_common_fields(ioc, "url", status, payload))
            if status == 200 and result.get("vt_raw_id"):
                result["verdict_source"] = "virustotal"
                verdict_locked = True

        # 3) Submission fallback — queue for phase 2
        if not verdict_locked and submit_missing and urlscan_client is not None:
            scan_url = ioc if (t_norm == "url" or ioc.startswith(("http://", "https://"))) else f"http://{ioc}/"
            status, payload, _ = urlscan_client.submit_url(scan_url, visibility=urlscan_visibility)
            if status == 200 and payload.get("uuid"):
                result["urlscan_scan_id"] = payload["uuid"]
                result["urlscan_permalink"] = payload.get("result")
                result["verdict_source"] = "urlscan_submit_pending"
            else:
                # Capture submit error for visibility
                msg = payload.get("message") or payload.get("description") or f"HTTP {status}"
                result.setdefault("vt_error", None)
                if not result["vt_error"]:
                    result["vt_error"] = f"URLScan submit failed: {msg}"

    elif t_norm == "ip":
        if use_vt and vt_client is not None:
            status, payload, _ = vt_client.get_ip(ioc)
            result.update(extract_common_fields(ioc, "ip", status, payload))
            if relationships and status == 200 and result.get("vt_raw_id"):
                _rs, rp, _ = vt_client.get_relationships("ip_addresses", ioc, "resolutions", limit=rel_limit)
                doms = [
                    {"type": "domain", "value": d.get("attributes", {}).get("host_name"), "source": "vt_resolutions"}
                    for d in (rp.get("data") or []) if d.get("attributes", {}).get("host_name")
                ]
                if doms:
                    result["additional_iocs"] = json.dumps(doms)
            if status == 200:
                result["verdict_source"] = "virustotal"

    elif t_norm == "file":
        if use_vt and vt_client is not None:
            status, payload, _ = vt_client.get_file(ioc)
            result.update(extract_common_fields(ioc, "file", status, payload))
            attrs = (payload.get("data") or {}).get("attributes", {}) if isinstance(payload, dict) else {}
            result.update(file_hash_triplet_from_attrs(attrs))
            if relationships and status == 200 and result.get("vt_raw_id"):
                file_id = result["vt_raw_id"]
                collected: List[Dict[str, str]] = []
                for rel_kind, ioc_kind in (("contacted_domains", "domain"), ("contacted_ips", "ip")):
                    _rs, rp, _ = vt_client.get_relationships("files", file_id, rel_kind, limit=rel_limit)
                    for d in (rp.get("data") or []):
                        if d.get("id"):
                            collected.append({"type": ioc_kind, "value": d["id"], "source": f"vt_{rel_kind}"})
                if collected:
                    result["additional_iocs"] = json.dumps(collected)
            if status == 200:
                result["verdict_source"] = "virustotal"
    else:
        result.update({"vt_http_status": None, "vt_error": "Unrecognized or unsupported IOC type."})

    # Compute composite (skip if still pending — phase 2 will recompute)
    if result["verdict_source"] != "urlscan_submit_pending":
        result.update(compute_composite_verdict(result))
    return result


def enrich_row_phase2(
    scan_id: str,
    urlscan_client: URLScanClient,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Poll a pending URLScan submission once. Returns (resolved, partial_columns).

    - resolved=True, cols populated when the scan finished AND had a usable verdict.
    - resolved=True, cols={'urlscan_scan_id': scan_id} when the scan finished but
      returned no opinion (score 0, no categories, no brands). Caller keeps existing
      urlscan_* columns from phase 1 (submit-response permalink/scan_id) and the
      composite falls through to VT or stays unknown.
    - resolved=False when scan isn't ready yet (HTTP 404 etc.).
    """
    status, payload, _ = urlscan_client.get_result(scan_id)
    if status == 200:
        v = urlscan_verdict_from_result(payload)
        if v:
            cols = _urlscan_cols_from_verdict(v)
            cols["urlscan_scan_id"] = scan_id
            return True, cols
        # Scan finished but no verdict — don't overwrite the submit-time columns.
        return True, {"urlscan_scan_id": scan_id}
    return False, {}


# Backward-compatible wrapper for vt_notebook.py and any external callers
def enrich_row(
    ioc: str,
    in_type_label: str,
    client: VTClient,
    relationships: bool = False,
    rel_limit: int = 5,
) -> Dict[str, Any]:
    """Legacy entry point — VT-only enrichment (no URLScan, no submission)."""
    return enrich_row_phase1(
        ioc=ioc,
        in_type_label=in_type_label,
        default_type=None,
        vt_client=client,
        urlscan_client=None,
        use_urlscan=False,
        use_vt=True,
        submit_missing=False,
        relationships=relationships,
        rel_limit=rel_limit,
    )


# -----------------------------
# Checkpoint
# -----------------------------
class Checkpoint:
    """
    Per-row enrichment checkpoint. Stores completed and pending rows keyed by
    a stable row key (row_index + ioc). Atomic writes (tmp + rename). Includes
    an input file sha256 fingerprint so resuming against a different input
    is detected and refused.

    On-disk schema:
        {
          "input_fingerprint": "<sha256>",
          "input_path": "...",
          "created_at": "<iso>",
          "rows": { "<key>": {<column>: <value>, ...} }
        }

    A "pending" row has verdict_source == "urlscan_submit_pending" and a
    `urlscan_scan_id`. Phase 2 resolves these in place.
    """

    def __init__(self, path: str, input_fingerprint: str, input_path: str):
        self.path = path
        self.input_fingerprint = input_fingerprint
        self.input_path = input_path
        self.rows: Dict[str, Dict[str, Any]] = {}
        self._load()

    @staticmethod
    def row_key(idx: int, ioc: str) -> str:
        return f"{idx}::{ioc}"

    def _load(self) -> None:
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return
        if not isinstance(data, dict):
            return
        existing_fp = data.get("input_fingerprint")
        if existing_fp and existing_fp != self.input_fingerprint:
            raise RuntimeError(
                f"Checkpoint at {self.path} was created for a different input file "
                f"(fingerprint mismatch). Delete it or point --checkpoint elsewhere to start fresh."
            )
        self.rows = dict(data.get("rows") or {})

    def _save(self) -> None:
        dir_ = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(dir_, exist_ok=True)
        payload = {
            "input_fingerprint": self.input_fingerprint,
            "input_path": self.input_path,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "rows": self.rows,
        }
        fd, tmp = tempfile.mkstemp(prefix=".vtckpt_", suffix=".tmp", dir=dir_)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    def get(self, idx: int, ioc: str) -> Optional[Dict[str, Any]]:
        return self.rows.get(self.row_key(idx, ioc))

    def is_complete(self, idx: int, ioc: str) -> bool:
        r = self.get(idx, ioc)
        if not r:
            return False
        return r.get("verdict_source") != "urlscan_submit_pending"

    def put(self, idx: int, ioc: str, record: Dict[str, Any]) -> None:
        self.rows[self.row_key(idx, ioc)] = record
        self._save()


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

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
    default_type: Optional[str] = None,
    console: Optional[Console] = None,
    print_each_row: bool = True,
    urlscan_api_key: Optional[str] = None,
    use_urlscan: bool = True,
    submit_missing: bool = True,
    urlscan_visibility: str = "unlisted",
    urlscan_stale_days: int = 90,
    checkpoint_path: Optional[str] = None,
    resume: bool = True,
    limit: Optional[int] = None,
    poll_initial_wait: int = 20,
    poll_second_wait: int = 30,
) -> pd.DataFrame:
    """
    Two-phase enrichment pipeline:

      Phase 1: walk all rows. For each domain/url IOC, try in order:
        URLScan search → VT fallback → submission (queued for phase 2).
        For ip/file: VT lookup. Each completed row is checkpointed atomically.

      Phase 2: poll any queued URLScan submissions. ≤2 polls per scan
        (one after initial wait, one after a second wait). Unresolved
        scans are written out with verdict_source='urlscan_submit_timeout'.
    """
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_api_key:
        raise RuntimeError("VIRUSTOTAL_API_KEY is not set in the environment.")
    if use_urlscan and not urlscan_api_key:
        raise RuntimeError("URLScan was requested but no URLSCAN_API_KEY/api key is configured.")

    logger = logging.getLogger("vt_enrich")

    df = pd.read_csv(input_csv_path, dtype=str, keep_default_na=False)

    resolved_ioc_idx = ioc_col_index if ioc_col_index is not None else IOC_COL_INDEX
    # type column may be absent — in that case caller must supply default_type
    resolved_type_idx = type_col_index
    needed_cols = (resolved_ioc_idx + 1) if resolved_type_idx is None else (max(resolved_ioc_idx, resolved_type_idx) + 1)
    if df.shape[1] < needed_cols:
        raise ValueError(
            f"Input CSV needs at least {needed_cols} column(s) for the selected IOC/type positions. Found {df.shape[1]}."
        )

    df["ioc"] = df.iloc[:, resolved_ioc_idx].astype(str).str.strip()
    if resolved_type_idx is not None:
        df["ioc_type_input"] = df.iloc[:, resolved_type_idx].astype(str).str.strip()
    else:
        df["ioc_type_input"] = ""

    if limit is not None and limit > 0:
        df = df.head(limit).reset_index(drop=True)

    # Clients
    vt_client = VTClient(api_key=vt_api_key, rate_per_min=rate_per_min, timeout=timeout, usage_tracker=usage_tracker)
    urlscan_client = (
        URLScanClient(api_key=urlscan_api_key, timeout=timeout, usage_tracker=usage_tracker)
        if use_urlscan and urlscan_api_key else None
    )

    # Checkpoint
    fingerprint = _file_sha256(input_csv_path)
    if checkpoint_path is None:
        checkpoint_path = output_csv_path + ".checkpoint.json"
    if not resume and os.path.isfile(checkpoint_path):
        os.remove(checkpoint_path)
    checkpoint = Checkpoint(checkpoint_path, input_fingerprint=fingerprint, input_path=os.path.abspath(input_csv_path))

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        transient=True,
    )

    enrich_records: List[Dict[str, Any]] = [None] * len(df)  # type: ignore[list-item]
    pending_indices: List[int] = []

    # ----- Phase 1 -----
    with progress:
        task_id = progress.add_task("Phase 1: lookup", total=len(df))
        for i, row in df.iterrows():
            ioc = row["ioc"]
            existing = checkpoint.get(i, ioc)
            if existing and checkpoint.is_complete(i, ioc):
                enrich_records[i] = existing
                progress.advance(task_id)
                continue
            if existing and existing.get("verdict_source") == "urlscan_submit_pending":
                # Keep the queued scan_id; phase 2 will resolve.
                enrich_records[i] = existing
                pending_indices.append(i)
                progress.advance(task_id)
                continue

            info = enrich_row_phase1(
                ioc=ioc,
                in_type_label=row["ioc_type_input"],
                default_type=default_type,
                vt_client=vt_client,
                urlscan_client=urlscan_client,
                urlscan_stale_days=urlscan_stale_days,
                use_urlscan=(urlscan_client is not None),
                use_vt=True,
                submit_missing=(submit_missing and urlscan_client is not None),
                urlscan_visibility=urlscan_visibility,
                relationships=relationships,
                rel_limit=relationships_limit,
            )
            enrich_records[i] = info
            checkpoint.put(i, ioc, info)
            if info.get("verdict_source") == "urlscan_submit_pending":
                pending_indices.append(i)
            progress.advance(task_id)

            if print_each_row and console is not None:
                src = info.get("verdict_source") or "none"
                score = info.get("maliciousness_score")
                summary = info.get("verdict_summary") or "-"
                icon = {
                    "urlscan_search": "[cyan]u[/cyan]",
                    "virustotal": "[yellow]v[/yellow]",
                    "urlscan_submit_pending": "[magenta]q[/magenta]",
                    "none": "[red]·[/red]",
                }.get(src, "·")
                score_str = f"{score:.0f}" if isinstance(score, (int, float)) else "-"
                console.print(f"{icon} [bold]{ioc}[/bold] [dim]{summary}[/dim] [white]score={score_str}[/white] [blue]{src}[/blue]")
            if info.get("vt_error"):
                logger.warning(f"IOC '{ioc}': {info.get('vt_error')}")

    # ----- Phase 2: poll pending URLScan submissions -----
    if pending_indices and urlscan_client is not None:
        if console is not None:
            console.print(f"\n[bold cyan]Phase 2:[/bold cyan] polling {len(pending_indices)} pending URLScan submissions")
        # First wait: scans need ~10-30s before they're ready
        if poll_initial_wait > 0:
            time.sleep(poll_initial_wait)

        # Pass 1
        still_pending: List[int] = []
        with progress:
            task_id = progress.add_task("Phase 2 pass 1", total=len(pending_indices))
            for i in pending_indices:
                rec = enrich_records[i]
                scan_id = rec.get("urlscan_scan_id")
                if not scan_id:
                    progress.advance(task_id)
                    continue
                resolved, cols = enrich_row_phase2(scan_id, urlscan_client)
                if resolved:
                    rec.update(cols)
                    rec["verdict_source"] = "urlscan_submit"
                    rec.update(compute_composite_verdict(rec))
                    checkpoint.put(i, df.iloc[i]["ioc"], rec)
                else:
                    still_pending.append(i)
                progress.advance(task_id)

        # Pass 2
        if still_pending:
            if poll_second_wait > 0:
                time.sleep(poll_second_wait)
            with progress:
                task_id = progress.add_task("Phase 2 pass 2", total=len(still_pending))
                for i in still_pending:
                    rec = enrich_records[i]
                    scan_id = rec.get("urlscan_scan_id")
                    if not scan_id:
                        progress.advance(task_id)
                        continue
                    resolved, cols = enrich_row_phase2(scan_id, urlscan_client)
                    if resolved:
                        rec.update(cols)
                        rec["verdict_source"] = "urlscan_submit"
                    else:
                        rec["verdict_source"] = "urlscan_submit_timeout"
                        rec.setdefault("vt_error", None)
                        rec["vt_error"] = (rec.get("vt_error") or "") + " | URLScan scan not ready after 2 polls"
                    rec.update(compute_composite_verdict(rec))
                    checkpoint.put(i, df.iloc[i]["ioc"], rec)
                    progress.advance(task_id)

    # ----- Build output frame -----
    enrich_df = pd.DataFrame([r if r is not None else {} for r in enrich_records])
    out = pd.concat([df.drop(columns=["ioc", "ioc_type_input"], errors="ignore"), enrich_df], axis=1)

    for col in ("vt_md5", "vt_sha1", "vt_sha256"):
        if col not in out.columns:
            out[col] = ""
        else:
            out[col] = out[col].fillna("")
    out["sha1_from_vt"] = out["vt_sha1"].where(out["vt_sha1"].ne(""), None)
    out["sha256_from_vt"] = out["vt_sha256"].where(out["vt_sha256"].ne(""), None)

    out.to_csv(output_csv_path, index=False, quoting=csv.QUOTE_MINIMAL)
    logger.info(f"Enriched CSV written to: {output_csv_path}")
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

    # --- URLScan options ---
    parser.add_argument(
        "--urlscan-api-key",
        dest="urlscan_api_key",
        default=None,
        help="URLScan API key. Falls back to URLSCAN_API_KEY env var or config file.",
    )
    us_group = parser.add_mutually_exclusive_group()
    us_group.add_argument(
        "--urlscan", dest="use_urlscan", action="store_true",
        help="Enable URLScan as primary lookup for domain/url IOCs.",
    )
    us_group.add_argument(
        "--no-urlscan", dest="use_urlscan", action="store_false",
        help="Disable URLScan entirely (VT only).",
    )
    parser.set_defaults(use_urlscan=None)

    sm_group = parser.add_mutually_exclusive_group()
    sm_group.add_argument(
        "--urlscan-submit-missing", dest="submit_missing", action="store_true",
        help="When URLScan/VT both return no verdict, submit a fresh URLScan scan and poll for results.",
    )
    sm_group.add_argument(
        "--no-urlscan-submit", dest="submit_missing", action="store_false",
        help="Disable URLScan submission fallback (default: enabled when URLScan is enabled).",
    )
    parser.set_defaults(submit_missing=None)

    parser.add_argument(
        "--urlscan-visibility",
        dest="urlscan_visibility",
        default=None,
        choices=["public", "unlisted", "private"],
        help="Visibility for URLScan submissions (default: unlisted).",
    )
    parser.add_argument(
        "--urlscan-stale-days",
        dest="urlscan_stale_days",
        type=int,
        default=None,
        help="A URLScan search hit older than this many days is treated as stale and falls through to VT (default: 90).",
    )

    # --- Input/output behavior ---
    parser.add_argument(
        "--default-type",
        dest="default_type",
        default=None,
        choices=["domain", "url", "ip", "file"],
        help="Type to use for every row when the input has no type column (e.g. 'domain' for a subdomain list).",
    )
    parser.add_argument(
        "--limit",
        dest="limit",
        type=int,
        default=None,
        help="Only process the first N rows. Useful for smoke-testing with N=1.",
    )

    # --- Resumability ---
    parser.add_argument(
        "--checkpoint",
        dest="checkpoint_path",
        default=None,
        help="Path to checkpoint sidecar JSON (default: <output>.checkpoint.json).",
    )
    resume_group = parser.add_mutually_exclusive_group()
    resume_group.add_argument(
        "--resume", dest="resume", action="store_true",
        help="Resume from existing checkpoint if present (default).",
    )
    resume_group.add_argument(
        "--no-resume", dest="resume", action="store_false",
        help="Ignore and overwrite any existing checkpoint.",
    )
    parser.set_defaults(resume=True)

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


def _resolve_effective(args, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce CLI args + config into a single dict of effective values."""
    def pick(cli_val, cfg_key, default):
        if cli_val is not None:
            return cli_val
        v = cfg.get(cfg_key)
        return default if v is None else v

    eff = {
        "rate_per_min": int(pick(args.rate_per_min, "rate_per_min", 4)),
        "timeout": int(pick(args.timeout, "timeout", 30)),
        "relationships": bool(pick(args.relationships, "relationships", False)),
        "relationships_limit": int(pick(args.relationships_limit, "relationships_limit", 5)),
        "daily_cap": int(pick(args.daily_cap, "daily_cap", 500)),
        "monthly_cap": int(pick(args.monthly_cap, "monthly_cap", 15500)),
        "usage_state_file": str(pick(args.usage_state_file, "usage_state_file", ".vt_usage.json")),
        "output_dir": str(pick(args.output_dir, "output_dir", "out")),
        "logs_dir": str(pick(args.logs_dir, "logs_dir", "logs")),
        "default_type": pick(args.default_type, "default_type", None),
        "use_urlscan": bool(pick(args.use_urlscan, "use_urlscan", True)),
        "submit_missing": bool(pick(args.submit_missing, "urlscan_submit_missing", True)),
        "urlscan_visibility": str(pick(args.urlscan_visibility, "urlscan_visibility", "unlisted")),
        "urlscan_stale_days": int(pick(args.urlscan_stale_days, "urlscan_stale_days", 90)),
        "limit": args.limit,
        "checkpoint_path": args.checkpoint_path,
        "resume": args.resume,
        # URLScan caps (used by UsageTracker for preflight + tracking)
        "urlscan_search_daily_cap": int(cfg.get("urlscan_search_daily_cap", 1000)),
        "urlscan_search_minute_cap": int(cfg.get("urlscan_search_minute_cap", 120)),
        "urlscan_submit_daily_cap": int(cfg.get("urlscan_submit_daily_cap", 1000)),
        "urlscan_submit_hourly_cap": int(cfg.get("urlscan_submit_hourly_cap", 100)),
        "urlscan_submit_minute_cap": int(cfg.get("urlscan_submit_minute_cap", 60)),
        "urlscan_retrieve_daily_cap": int(cfg.get("urlscan_retrieve_daily_cap", 10000)),
    }
    return eff


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    console = Console()
    cfg = _load_config(args.config_path)

    # VT API key precedence: CLI > ENV > CONFIG
    if args.api_key:
        os.environ["VIRUSTOTAL_API_KEY"] = args.api_key
    elif not os.getenv("VIRUSTOTAL_API_KEY"):
        api_key_from_cfg = cfg.get("api_key") if isinstance(cfg, dict) else None
        if api_key_from_cfg:
            os.environ["VIRUSTOTAL_API_KEY"] = str(api_key_from_cfg)

    # URLScan API key precedence: CLI > ENV (URLSCAN_API_KEY) > CONFIG
    urlscan_api_key = (
        args.urlscan_api_key
        or os.getenv("URLSCAN_API_KEY")
        or (cfg.get("urlscan_api_key") if isinstance(cfg, dict) else None)
    )

    input_csv_path = args.input_csv
    output_csv_path = args.output_csv
    eff = _resolve_effective(args, cfg)

    # If the user has no URLScan key, silently disable it.
    if not urlscan_api_key:
        eff["use_urlscan"] = False
        eff["submit_missing"] = False

    session_id = datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{uuid.uuid4().hex[:6]}"
    daily_key = date.today().isoformat()
    daily_output_dir = os.path.abspath(os.path.join(eff["output_dir"], daily_key))
    daily_logs_dir = os.path.abspath(os.path.join(eff["logs_dir"], daily_key))
    os.makedirs(daily_output_dir, exist_ok=True)
    os.makedirs(daily_logs_dir, exist_ok=True)

    log_path = os.path.join(daily_logs_dir, f"vt_enrich_{session_id}.log")
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    rich_handler = RichHandler(rich_tracebacks=False, markup=True, console=console)
    rich_handler.setLevel(logging.INFO)
    rich_handler.setFormatter(logging.Formatter("%(message)s"))
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root_logger.handlers = []
    root_logger.addHandler(rich_handler)
    root_logger.addHandler(file_handler)
    logger = logging.getLogger("vt_enrich")

    caps = {
        ACTION_VT: {"daily": eff["daily_cap"], "monthly": eff["monthly_cap"]},
        ACTION_URLSCAN_SEARCH: {"daily": eff["urlscan_search_daily_cap"], "minute": eff["urlscan_search_minute_cap"]},
        ACTION_URLSCAN_SUBMIT: {
            "daily": eff["urlscan_submit_daily_cap"],
            "hourly": eff["urlscan_submit_hourly_cap"],
            "minute": eff["urlscan_submit_minute_cap"],
        },
        ACTION_URLSCAN_RETRIEVE: {"daily": eff["urlscan_retrieve_daily_cap"]},
    }
    usage_tracker = UsageTracker(
        state_file=os.path.abspath(eff["usage_state_file"]),
        caps=caps,
    )

    # Preflight
    try:
        df_preview = pd.read_csv(input_csv_path, dtype=str, keep_default_na=False)
        ioc_selector = args.ioc_col if args.ioc_col is not None else (cfg.get("ioc_col") if cfg.get("ioc_col") is not None else "Query")
        type_selector = args.type_col if args.type_col is not None else cfg.get("type_col")

        ioc_col_index = _column_selector_to_index(ioc_selector, df=df_preview, default_index=IOC_COL_INDEX)

        # type col is optional — if user provided default_type and no type_selector resolves to a real column, skip it
        type_col_index: Optional[int] = None
        if type_selector is not None:
            try:
                t_idx = _column_selector_to_index(type_selector, df=df_preview, default_index=-1)
                if t_idx >= 0 and t_idx < df_preview.shape[1]:
                    type_col_index = t_idx
            except Exception:
                type_col_index = None
        if type_col_index is None and eff["default_type"] is None and df_preview.shape[1] > TYPE_COL_INDEX:
            # Legacy positional fallback when caller didn't set default_type
            type_col_index = TYPE_COL_INDEX

        if type_col_index is None and eff["default_type"] is None:
            raise ValueError(
                "No type column found and --default-type not set. "
                "Pass --default-type domain (e.g., for a flat subdomain list) or specify --type-col."
            )

        num_rows = len(df_preview)
        if eff["limit"]:
            num_rows = min(num_rows, eff["limit"])

        info_table = Table(title="Preflight Estimate", show_edge=True, header_style="bold cyan")
        info_table.add_column("Metric", style="bold")
        info_table.add_column("Value")
        info_table.add_row("Rows to process", str(num_rows))
        info_table.add_row("Default IOC type", str(eff["default_type"] or "(from type col)"))
        info_table.add_row("URLScan", "enabled" if eff["use_urlscan"] else "disabled")
        info_table.add_row("URLScan submit fallback", "enabled" if (eff["use_urlscan"] and eff["submit_missing"]) else "disabled")
        info_table.add_row("URLScan stale threshold", f"{eff['urlscan_stale_days']} days")
        info_table.add_row("VT pacing", f"{eff['rate_per_min']}/min")
        info_table.add_row("VT remaining today", f"{usage_tracker.remaining(ACTION_VT, 'daily')} / {eff['daily_cap']}")
        if eff["use_urlscan"]:
            info_table.add_row(
                "URLScan search remaining today",
                f"{usage_tracker.remaining(ACTION_URLSCAN_SEARCH, 'daily')} / {eff['urlscan_search_daily_cap']}",
            )
            if eff["submit_missing"]:
                info_table.add_row(
                    "URLScan submit remaining today",
                    f"{usage_tracker.remaining(ACTION_URLSCAN_SUBMIT, 'daily')} / {eff['urlscan_submit_daily_cap']}",
                )

        warnings: List[str] = []
        if eff["use_urlscan"]:
            if num_rows > usage_tracker.remaining(ACTION_URLSCAN_SEARCH, "daily"):
                warnings.append("URLScan search may exceed today's cap")
        else:
            if num_rows > usage_tracker.remaining(ACTION_VT, "daily"):
                warnings.append("VT calls may exceed today's daily cap")
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
        ioc_col_index, type_col_index = IOC_COL_INDEX, TYPE_COL_INDEX  # safe fallbacks

    try:
        final_output_path = output_csv_path
        input_base = os.path.splitext(os.path.basename(input_csv_path))[0]
        if final_output_path:
            if os.path.isdir(final_output_path):
                final_output_path = os.path.join(final_output_path, f"{input_base}.{session_id}.enriched.csv")
            elif not final_output_path.lower().endswith(".csv"):
                os.makedirs(final_output_path, exist_ok=True)
                final_output_path = os.path.join(final_output_path, f"{input_base}.{session_id}.enriched.csv")
            else:
                os.makedirs(os.path.dirname(os.path.abspath(final_output_path)) or ".", exist_ok=True)
        else:
            final_output_path = os.path.join(daily_output_dir, f"{input_base}.{session_id}.enriched.csv")

        logger.info(f"Writing output to: {final_output_path}")
        logger.info(f"Session log: {log_path}")

        df = process_csv(
            input_csv_path=input_csv_path,
            output_csv_path=final_output_path,
            rate_per_min=eff["rate_per_min"],
            timeout=eff["timeout"],
            relationships=eff["relationships"],
            relationships_limit=eff["relationships_limit"],
            usage_tracker=usage_tracker,
            ioc_col_index=ioc_col_index,
            type_col_index=type_col_index,
            default_type=eff["default_type"],
            console=console,
            print_each_row=args.row_print,
            urlscan_api_key=urlscan_api_key,
            use_urlscan=eff["use_urlscan"],
            submit_missing=eff["submit_missing"],
            urlscan_visibility=eff["urlscan_visibility"],
            urlscan_stale_days=eff["urlscan_stale_days"],
            checkpoint_path=eff["checkpoint_path"],
            resume=eff["resume"],
            limit=eff["limit"],
        )

        # Summary
        if "verdict_source" in df.columns:
            counts = df["verdict_source"].fillna("none").value_counts().to_dict()
            console.print(f"[bold green][+] Rows processed:[/bold green] {len(df)}")
            for k, v in counts.items():
                console.print(f"  [dim]{k}:[/dim] {v}")
        else:
            console.print(f"[bold green][+] Rows processed:[/bold green] {len(df)}")
        console.print(f"[bold]Output:[/bold] {final_output_path}")
        console.print(f"[bold]Log:[/bold] {log_path}")
        return 0
    except Exception as exc:
        console.print(f"[red][!][/red] Error: {exc}")
        logger.exception("Run failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
