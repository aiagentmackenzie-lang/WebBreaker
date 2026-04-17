"""Scan Orchestrator — coordinates all scanner modules in a unified workflow."""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional, Callable

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from .config import ScanConfig, Finding, Severity, FindingType
from .database import Database
from .http_client import HttpClient
from .recon import ReconScanner
from .sqli import SQLiScanner
from .xss import XSSScanner
from .csrf import CSRFScanner
from .cmdi import CmdiScanner
from .lfi import LFIScanner
from .rfi import RFIScanner
from .dirbrute import DirBruteScanner
from .fuzz import FuzzScanner
from .headers import HeaderScanner
from .session import SessionScanner

console = Console()

ALL_MODULES = ["recon", "sqli", "xss", "csrf", "cmdi", "lfi", "rfi", "dirbrute", "fuzz", "headers", "session"]


class ScanOrchestrator:
    """Coordinates the full web application pentest scan."""

    def __init__(self, config: ScanConfig, db_path: str = "webbreaker.db"):
        self.config = config
        self.scan_id = str(uuid.uuid4())[:8]
        self.db = Database(db_path)
        self.db.connect()
        self.findings: list[Finding] = []
        self.recon_results = None
        self._progress_callback: Optional[Callable] = None
        self._module_status: dict[str, str] = {}

    def on_progress(self, callback: Callable):
        self._progress_callback = callback

    def _notify(self, module: str, message: str):
        self._module_status[module] = message
        if self._progress_callback:
            self._progress_callback(module, message)

    async def run(self, modules: Optional[list[str]] = None) -> list[Finding]:
        """Execute the full scan workflow."""
        if modules is None:
            modules = self.config.modules or ALL_MODULES

        # Create scan in DB
        self.db.create_scan(self.scan_id, self.config.target, {
            "modules": modules,
            "depth": self.config.depth,
            "threads": self.config.threads,
        })

        console.print(f"\n[bold red]🔥 WebBreaker[/] — Web Application Pentest Toolkit")
        console.print(f"[dim]Scan ID: {self.scan_id}[/dim]")
        console.print(f"[bold]Target:[/] {self.config.target}")
        console.print(f"[bold]Modules:[/] {', '.join(modules)}\n")

        all_findings = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(modules))

            # Phase 1: Always do recon first (needed for other modules)
            recon_data = None
            if "recon" in modules:
                self._notify("recon", "Running reconnaissance & spidering...")
                recon = ReconScanner(self.config)
                recon_data = await recon.spider(self.config.target)
                self.recon_results = recon_data

                # Store recon in DB
                for r in recon_data:
                    self.db.insert_recon(
                        self.scan_id, r.url, r.method, r.status_code,
                        r.content_length, r.content_type,
                        ",".join(r.tech), r.forms, r.links, r.params, r.depth,
                    )

                console.print(f"  [green]✓[/] Recon: {len(recon_data)} URLs, {len(recon.get_all_forms())} forms, tech: {', '.join(recon.get_detected_tech())}")
                await recon.close()
                progress.update(task, advance=1)

            # Phase 2: Run vulnerability scanners
            urls = [r.url for r in recon_data] if recon_data else [self.config.target]
            forms = recon_data[0].forms if recon_data and recon_data else []

            scan_modules = [m for m in modules if m != "recon"]

            for module_name in scan_modules:
                self._notify(module_name, f"Running {module_name.upper()} scan...")

                if module_name == "sqli":
                    scanner = SQLiScanner(self.config)
                    for url in urls:
                        params = None
                        if recon_data:
                            for r in recon_data:
                                if r.url == url and r.params:
                                    params = r.params
                                    break
                        findings = await scanner.scan_url(url, params)
                        all_findings.extend(findings)
                    # Also scan forms
                    if forms:
                        form_findings = await scanner.scan_forms(forms)
                        all_findings.extend(form_findings)
                    await scanner.close()

                elif module_name == "xss":
                    scanner = XSSScanner(self.config)
                    for url in urls:
                        findings = await scanner.scan_url(url)
                        all_findings.extend(findings)
                    if forms:
                        form_findings = await scanner.scan_forms(forms)
                        all_findings.extend(form_findings)
                    await scanner.close()

                elif module_name == "csrf":
                    scanner = CSRFScanner(self.config)
                    if forms:
                        findings = await scanner.scan_forms(forms, self.config.target)
                        all_findings.extend(findings)
                    await scanner.close()

                elif module_name == "cmdi":
                    scanner = CmdiScanner(self.config)
                    for url in urls:
                        findings = await scanner.scan_url(url)
                        all_findings.extend(findings)
                    if forms:
                        form_findings = await scanner.scan_forms(forms)
                        all_findings.extend(form_findings)
                    await scanner.close()

                elif module_name == "lfi":
                    scanner = LFIScanner(self.config)
                    for url in urls:
                        findings = await scanner.scan_url(url)
                        all_findings.extend(findings)
                    await scanner.close()

                elif module_name == "rfi":
                    scanner = RFIScanner(self.config)
                    for url in urls:
                        findings = await scanner.scan_url(url)
                        all_findings.extend(findings)
                    await scanner.close()

                elif module_name == "dirbrute":
                    scanner = DirBruteScanner(self.config)
                    await scanner.scan(self.config.target)
                    all_findings.extend(scanner.findings)
                    await scanner.close()

                elif module_name == "fuzz":
                    scanner = FuzzScanner(self.config)
                    for url in urls:
                        findings = await scanner.scan_url(url)
                        all_findings.extend(findings)
                    await scanner.close()

                elif module_name == "headers":
                    scanner = HeaderScanner(self.config)
                    for url in urls[:5]:  # Only check first 5 URLs for headers
                        findings = await scanner.scan(url)
                        all_findings.extend(findings)
                    console.print(f"  [green]✓[/] Security Header Grade: [bold]{scanner.grade}[/bold]")
                    await scanner.close()

                elif module_name == "session":
                    scanner = SessionScanner(self.config)
                    for url in urls[:5]:
                        findings = await scanner.scan(url)
                        all_findings.extend(findings)
                    await scanner.close()

                # Store findings in DB
                for f in all_findings:
                    self.db.insert_finding(self.scan_id, f)

                count = len([f for f in all_findings if f.finding_type.value == module_name.upper() or
                            (module_name == "dirbrute" and f.finding_type == FindingType.DIRBRUTE) or
                            (module_name == "headers" and f.finding_type == FindingType.HEADERS) or
                            (module_name == "session" and f.finding_type == FindingType.SESSION) or
                            (module_name == "fuzz" and f.finding_type == FindingType.FUZZ)])

                console.print(f"  [green]✓[/] {module_name.upper()}: {count} findings")
                progress.update(task, advance=1)

        # Deduplicate findings
        seen = set()
        unique_findings = []
        for f in all_findings:
            key = (f.url, f.parameter, f.payload[:50], f.finding_type.value)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        self.findings = unique_findings

        # Update scan status
        self.db.update_scan_status(self.scan_id, "completed", len(unique_findings))

        # Print summary
        self._print_summary(unique_findings)

        return unique_findings

    def _print_summary(self, findings: list[Finding]):
        """Print a rich summary table of findings."""
        console.print()

        # Severity breakdown
        by_severity = {}
        for f in findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

        severity_table = Table(title="📊 Findings Summary", show_header=True, header_style="bold red")
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count", justify="right")

        colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "green", "INFO": "dim"}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in by_severity:
                severity_table.add_row(f"[{colors[sev]}]{sev}[/{colors[sev]}]", str(by_severity[sev]))

        console.print(severity_table)

        # Type breakdown
        by_type = {}
        for f in findings:
            by_type[f.finding_type.value] = by_type.get(f.finding_type.value, 0) + 1

        type_table = Table(title="📋 By Type", show_header=True, header_style="bold blue")
        type_table.add_column("Type")
        type_table.add_column("Count", justify="right")
        for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
            type_table.add_row(t, str(c))

        console.print(type_table)

        # Top findings
        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if critical_high:
            console.print(Panel(
                "\n".join(f"• [{colors[f.severity.value]}]{f.severity.value}[/] {f.finding_type.value}: {f.url} param={f.parameter}" for f in critical_high[:10]),
                title="🚨 Critical & High Findings",
                border_style="red",
            ))

        console.print(f"\n[bold]Total findings:[/] {len(findings)} | Scan ID: {self.scan_id}")

    def close(self):
        self.db.close()