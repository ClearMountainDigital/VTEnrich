"""
VTEnrich Notebook Interface

This module provides notebook-friendly functions for VTEnrich without CLI arguments.
You can configure settings in a cell and run enrichment jobs interactively.

Built by Chris Cooley
"""

import os
import sys
import pandas as pd
from datetime import datetime, date
import uuid
import logging
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, BarColumn, TimeRemainingColumn, TimeElapsedColumn, SpinnerColumn, TextColumn

# Import VTEnrich components
from VTEnrich import (
    VTClient, URLScanClient, UsageTracker, enrich_row, enrich_row_phase1,
    enrich_row_phase2, _column_selector_to_index, extract_common_fields,
    file_hash_triplet_from_attrs, compute_composite_verdict, _load_config,
    ACTION_VT, ACTION_URLSCAN_SEARCH, ACTION_URLSCAN_SUBMIT, ACTION_URLSCAN_RETRIEVE,
)


class VTNotebook:
    """
    A notebook-friendly interface for VTEnrich functionality.
    """
    
    def __init__(self, config=None, config_file=None):
        """
        Initialize VTNotebook with configuration.
        
        Args:
            config: Dict with configuration options, or None to use defaults
            config_file: Path to JSON config file to load, or None
        """
        self.console = Console()
        
        # Load configuration
        if config_file:
            file_config = _load_config(config_file)
        else:
            file_config = _load_config(None)  # Try auto-detection
            
        # Default configuration
        default_config = {
            "api_key": "YOUR_VIRUSTOTAL_API_KEY_HERE",
            "urlscan_api_key": None,
            "rate_per_min": 4,
            "timeout": 30,
            "relationships": False,
            "relationships_limit": 5,
            "daily_cap": 500,
            "monthly_cap": 15500,
            "usage_state_file": ".vt_usage.json",
            "output_dir": "out",
            "logs_dir": "logs",
            "ioc_col": "Query",
            "type_col": None,
            "default_type": "domain",
            "use_urlscan": True,
            "urlscan_submit_missing": True,
            "urlscan_visibility": "unlisted",
            "urlscan_stale_days": 90,
            "urlscan_search_daily_cap": 1000,
            "urlscan_search_minute_cap": 120,
            "urlscan_submit_daily_cap": 1000,
            "urlscan_submit_hourly_cap": 100,
            "urlscan_submit_minute_cap": 60,
            "urlscan_retrieve_daily_cap": 10000,
        }
        
        # Merge configs: user provided > config file > defaults
        self.config = default_config.copy()
        self.config.update(file_config)
        if config:
            self.config.update(config)
            
        # Initialize session
        self.session_id = datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{uuid.uuid4().hex[:6]}"
        self.daily_key = date.today().isoformat()
        
        # Setup directories
        self.daily_output_dir = os.path.abspath(os.path.join(self.config["output_dir"], self.daily_key))
        self.daily_logs_dir = os.path.abspath(os.path.join(self.config["logs_dir"], self.daily_key))
        os.makedirs(self.daily_output_dir, exist_ok=True)
        os.makedirs(self.daily_logs_dir, exist_ok=True)
        
        # Setup logging
        self.log_path = os.path.join(self.daily_logs_dir, f"vt_enrich_{self.session_id}.log")
        self._setup_logging()
        
        # Initialize components
        self._initialize_components()
        
        # Show welcome banner
        self._show_banner()
    
    def _setup_logging(self):
        """Configure logging for the session."""
        # Create a logger specifically for this session
        self.logger = logging.getLogger(f"vt_enrich_{self.session_id}")
        self.logger.setLevel(logging.DEBUG)
        
        # Remove any existing handlers
        self.logger.handlers = []
        
        # File handler
        file_handler = logging.FileHandler(self.log_path, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        self.logger.addHandler(file_handler)
        
        # Console handler (optional, can be disabled)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(console_handler)
    
    def _initialize_components(self):
        """Initialize VT + URLScan clients and usage tracker."""
        os.environ["VIRUSTOTAL_API_KEY"] = self.config["api_key"]

        caps = {
            ACTION_VT: {"daily": self.config["daily_cap"], "monthly": self.config["monthly_cap"]},
            ACTION_URLSCAN_SEARCH: {
                "daily": self.config["urlscan_search_daily_cap"],
                "minute": self.config["urlscan_search_minute_cap"],
            },
            ACTION_URLSCAN_SUBMIT: {
                "daily": self.config["urlscan_submit_daily_cap"],
                "hourly": self.config["urlscan_submit_hourly_cap"],
                "minute": self.config["urlscan_submit_minute_cap"],
            },
            ACTION_URLSCAN_RETRIEVE: {"daily": self.config["urlscan_retrieve_daily_cap"]},
        }
        self.usage_tracker = UsageTracker(
            state_file=os.path.abspath(self.config["usage_state_file"]),
            caps=caps,
        )

        self.client = VTClient(
            api_key=self.config["api_key"],
            rate_per_min=self.config["rate_per_min"],
            timeout=self.config["timeout"],
            usage_tracker=self.usage_tracker,
        )

        urlscan_key = self.config.get("urlscan_api_key") or os.getenv("URLSCAN_API_KEY")
        if self.config.get("use_urlscan") and urlscan_key:
            self.urlscan_client = URLScanClient(
                api_key=urlscan_key,
                timeout=self.config["timeout"],
                usage_tracker=self.usage_tracker,
            )
        else:
            self.urlscan_client = None
            if self.config.get("use_urlscan") and not urlscan_key:
                self.console.print("[yellow]URLScan key not configured — running VT-only.[/yellow]")
    
    def _show_banner(self):
        """Display welcome banner."""
        banner = Panel(
            Text.from_markup(
                "[bold cyan]VTEnrich Notebook Interface[/bold cyan]\n"
                "[white]Built by [bold]Chris Cooley[/bold][/white]"
            ),
            title="Welcome",
            border_style="magenta",
        )
        self.console.print(banner)
        self.console.print(f"Session ID: {self.session_id}")
        self.console.print(f"Log file: {self.log_path}")
        self.console.print(f"Usage tracker: {self.config['usage_state_file']}")
    
    def show_config(self):
        """Display current configuration."""
        config_table = Table(title="Current Configuration", show_edge=True, header_style="bold cyan")
        config_table.add_column("Setting", style="bold")
        config_table.add_column("Value")
        
        for key, value in self.config.items():
            if key == "api_key":
                # Mask API key for security
                display_value = value[:8] + "..." if len(str(value)) > 8 else "***"
            else:
                display_value = str(value)
            config_table.add_row(key, display_value)
        
        self.console.print(config_table)
    
    def show_usage(self):
        """Display current API usage and quotas."""
        remaining_today = self.usage_tracker.remaining_today()
        remaining_month = self.usage_tracker.remaining_month()
        used_today = self.usage_tracker.get_today_counts()
        used_month = self.usage_tracker.get_month_counts()
        
        usage_table = Table(title="Current Usage Status", show_edge=True, header_style="bold cyan")
        usage_table.add_column("Period", style="bold")
        usage_table.add_column("Used")
        usage_table.add_column("Remaining")
        usage_table.add_column("Total Cap")
        
        usage_table.add_row("Today", str(used_today), str(remaining_today), str(self.config["daily_cap"]))
        usage_table.add_row("This Month", str(used_month), str(remaining_month), str(self.config["monthly_cap"]))
        
        self.console.print(usage_table)
        return {
            "today": {"used": used_today, "remaining": remaining_today, "cap": self.config["daily_cap"]},
            "month": {"used": used_month, "remaining": remaining_month, "cap": self.config["monthly_cap"]}
        }
    
    def preview_csv(self, csv_path):
        """Load and preview a CSV file."""
        try:
            df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
            self.console.print(f"CSV loaded: {len(df)} rows, {len(df.columns)} columns")
            self.console.print("\nColumn headers:")
            for i, col in enumerate(df.columns):
                self.console.print(f"  {i}: {col}")
            
            self.console.print("\nFirst few rows:")
            return df.head()
        except Exception as e:
            self.console.print(f"[red]Error loading CSV: {e}[/red]")
            return None
    
    def preflight_check(self, csv_path, ioc_col=None, type_col=None):
        """
        Perform preflight check on a CSV to estimate processing time and quota usage.
        
        Args:
            csv_path: Path to CSV file
            ioc_col: IOC column selector (overrides config)
            type_col: Type column selector (overrides config)
        
        Returns:
            Dict with preflight information
        """
        try:
            df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
            
            # Resolve column indices (type col may be absent when default_type is set)
            ioc_selector = ioc_col if ioc_col is not None else self.config["ioc_col"]
            type_selector = type_col if type_col is not None else self.config.get("type_col")

            ioc_col_index = _column_selector_to_index(ioc_selector, df=df, default_index=2)
            type_col_index = None
            if type_selector is not None:
                t_idx = _column_selector_to_index(type_selector, df=df, default_index=-1)
                if 0 <= t_idx < df.shape[1]:
                    type_col_index = t_idx

            need = ioc_col_index + 1 if type_col_index is None else max(ioc_col_index, type_col_index) + 1
            if df.shape[1] < need:
                raise ValueError(f"CSV needs at least {need} columns")

            num_rows = len(df)
            minutes_estimate = UsageTracker.estimate_minutes(num_rows, self.config["rate_per_min"])
            est_str = f"~{int(minutes_estimate)} minutes" if minutes_estimate < 60 else f"~{minutes_estimate/60:.1f} hours"
            
            remaining_today = self.usage_tracker.remaining_today()
            remaining_month = self.usage_tracker.remaining_month()
            exceed_daily, exceed_month = self.usage_tracker.will_exceed_caps(num_rows)
            
            # Show preflight table
            info_table = Table(title="Preflight Estimate", show_edge=True, header_style="bold cyan")
            info_table.add_column("Metric", style="bold")
            info_table.add_column("Value")
            info_table.add_row("Rows to process", str(num_rows))
            info_table.add_row("Rate (per min)", str(self.config["rate_per_min"]))
            info_table.add_row("Estimated time", est_str)
            info_table.add_row("Remaining today", f"{remaining_today} / {self.config['daily_cap']}")
            info_table.add_row("Remaining month", f"{remaining_month} / {self.config['monthly_cap']}")
            
            warnings = []
            if exceed_daily:
                warnings.append("Exceeds daily cap")
            if exceed_month:
                warnings.append("Exceeds monthly cap")
            if warnings:
                info_table.add_row("Warnings", ", ".join(warnings))
            
            self.console.print(Panel(info_table, title=f"Session {self.session_id}", border_style="green"))
            
            if warnings:
                self.console.print("[red]⚠️  WARNING: This run would exceed your quotas![/red]")
            
            return {
                "rows": num_rows,
                "estimated_minutes": minutes_estimate,
                "remaining_today": remaining_today,
                "remaining_month": remaining_month,
                "exceed_daily": exceed_daily,
                "exceed_month": exceed_month,
                "warnings": warnings
            }
            
        except Exception as e:
            self.console.print(f"[red]Preflight check failed: {e}[/red]")
            return None
    
    def enrich_csv(self, csv_path, output_path=None, ioc_col=None, type_col=None, show_progress=True):
        """
        Enrich a CSV file with VirusTotal data.
        
        Args:
            csv_path: Path to input CSV file
            output_path: Path for output CSV (auto-generated if None)
            ioc_col: IOC column selector (overrides config)
            type_col: Type column selector (overrides config)
            show_progress: Whether to show per-row progress
        
        Returns:
            Enriched DataFrame
        """
        try:
            # Load CSV
            df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
            
            # Resolve column indices (type col may be absent when default_type is set)
            ioc_selector = ioc_col if ioc_col is not None else self.config["ioc_col"]
            type_selector = type_col if type_col is not None else self.config.get("type_col")

            ioc_col_index = _column_selector_to_index(ioc_selector, df=df, default_index=2)
            type_col_index = None
            if type_selector is not None:
                t_idx = _column_selector_to_index(type_selector, df=df, default_index=-1)
                if 0 <= t_idx < df.shape[1]:
                    type_col_index = t_idx

            self.console.print(f"Using IOC column: {ioc_col_index} ('{df.columns[ioc_col_index]}')")
            if type_col_index is not None:
                self.console.print(f"Using type column: {type_col_index} ('{df.columns[type_col_index]}')")
            else:
                self.console.print(f"No type column — defaulting every row to: {self.config.get('default_type') or '(auto)'}")

            df["ioc"] = df.iloc[:, ioc_col_index].astype(str).str.strip()
            if type_col_index is not None:
                df["ioc_type_input"] = df.iloc[:, type_col_index].astype(str).str.strip()
            else:
                df["ioc_type_input"] = ""
            
            # Process each row
            enrich_records = []
            
            if show_progress:
                progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TimeElapsedColumn(),
                    TimeRemainingColumn(),
                    transient=True,
                )
                with progress:
                    task_id = progress.add_task("Enriching rows", total=len(df))
                    for _, row in df.iterrows():
                        info = self._enrich_single_row(row, show_progress)
                        enrich_records.append(info)
                        progress.advance(task_id)
            else:
                self.console.print(f"Processing {len(df)} rows...")
                for _, row in df.iterrows():
                    info = self._enrich_single_row(row, show_progress)
                    enrich_records.append(info)
            
            # Create result DataFrame
            enrich_df = pd.DataFrame(enrich_records)
            result_df = pd.concat([df, enrich_df], axis=1)
            
            # Fill missing columns
            for col in ("vt_md5", "vt_sha1", "vt_sha256"):
                if col not in result_df.columns:
                    result_df[col] = ""
                else:
                    result_df[col] = result_df[col].fillna("")
            
            # Add convenience columns
            result_df["sha1_from_vt"] = result_df["vt_sha1"].where(result_df["vt_sha1"].ne(""), None)
            result_df["sha256_from_vt"] = result_df["vt_sha256"].where(result_df["vt_sha256"].ne(""), None)
            
            # Determine output path
            if not output_path:
                input_base = os.path.splitext(os.path.basename(csv_path))[0]
                output_path = os.path.join(self.daily_output_dir, f"{input_base}.{self.session_id}.enriched.csv")
            
            # Save to CSV
            result_df.to_csv(output_path, index=False)
            
            self.console.print(f"[bold green]✅ Enriched data saved to:[/bold green] {output_path}")
            self.console.print(f"[bold]Log file:[/bold] {self.log_path}")
            self.console.print(f"[bold]Session ID:[/bold] {self.session_id}")
            
            return result_df
            
        except Exception as e:
            self.console.print(f"[red]Enrichment failed: {e}[/red]")
            self.logger.error(f"Enrichment failed: {e}")
            return None
    
    def _enrich_single_row(self, row, show_progress=True):
        """Enrich a single row using the multi-provider chain."""
        try:
            info = enrich_row_phase1(
                ioc=row["ioc"],
                in_type_label=row["ioc_type_input"],
                default_type=self.config.get("default_type"),
                vt_client=self.client,
                urlscan_client=self.urlscan_client,
                urlscan_stale_days=self.config["urlscan_stale_days"],
                use_urlscan=self.urlscan_client is not None,
                use_vt=True,
                # Notebook does no phase-2 polling, so don't queue submissions here.
                # Use the CLI for jobs that need URLScan submission fallback.
                submit_missing=False,
                urlscan_visibility=self.config.get("urlscan_visibility", "unlisted"),
                relationships=self.config["relationships"],
                rel_limit=self.config["relationships_limit"],
            )

            if show_progress:
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
                self.console.print(
                    f"{icon} [bold]{row['ioc']}[/bold] [dim]{summary}[/dim] "
                    f"[white]score={score_str}[/white] [blue]{src}[/blue]"
                )
                if info.get("vt_error"):
                    self.console.print(f"   [yellow]Warning:[/yellow] {info.get('vt_error')}")
            return info
        except Exception as e:
            self.logger.error(f"Error processing {row['ioc']}: {e}")
            return {
                "normalized_type": None,
                "derived_domain_from_url": None,
                "additional_iocs": "[]",
                "vt_md5": None, "vt_sha1": None, "vt_sha256": None,
                "vt_error": f"Processing error: {e}",
                "verdict_source": "none",
                "maliciousness_score": None,
                "verdict_summary": "unknown",
            }


# Convenience functions for quick usage
def create_session(config=None, config_file=None):
    """
    Create a new VTNotebook session.
    
    Args:
        config: Dict with configuration options
        config_file: Path to JSON config file
    
    Returns:
        VTNotebook instance
    """
    return VTNotebook(config=config, config_file=config_file)


def quick_enrich(csv_path, api_key=None, config_file=None, **kwargs):
    """
    Quick enrichment function for simple use cases.
    
    Args:
        csv_path: Path to CSV file
        api_key: VirusTotal API key (optional if in config/env)
        config_file: Path to config file (optional)
        **kwargs: Additional config options
    
    Returns:
        Enriched DataFrame
    """
    config = {}
    if api_key:
        config["api_key"] = api_key
    config.update(kwargs)
    
    session = VTNotebook(config=config, config_file=config_file)
    return session.enrich_csv(csv_path)
