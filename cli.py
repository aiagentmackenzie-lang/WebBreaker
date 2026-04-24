#!/usr/bin/env python3
"""WebBreaker CLI — Web Application Penetration Testing Toolkit."""

import sys
import json
import asyncio
from datetime import datetime, timezone

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def print_banner():
    console.print(Panel(
        "[bold red]🔥 WebBreaker[/]\n[dim]Web Application Penetration Testing Toolkit v1.0[/]\n"
        "[dim]For authorized security assessments only.[/]",
        border_style="red",
    ))


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """WebBreaker — Web Application Penetration Testing Toolkit."""
    pass


@cli.command()
@click.argument("target")
@click.option("--auth", is_flag=True, help="Confirm you have authorized access to test this target")
@click.option("--modules", "-m", default="all", help="Comma-separated modules: recon,sqli,xss,csrf,cmdi,lfi,rfi,dirbrute,fuzz,headers,session")
@click.option("--depth", "-d", default=3, type=int, help="Spider depth (default: 3)")
@click.option("--threads", "-t", default=20, type=int, help="Concurrent threads (default: 20)")
@click.option("--timeout", default=10, type=int, help="Request timeout in seconds (default: 10)")
@click.option("--delay", default=0.0, type=float, help="Delay between requests in seconds (default: 0)")
@click.option("--proxy", default=None, help="HTTP proxy URL (e.g., http://127.0.0.1:8080)")
@click.option("--auth-header", default=None, help="Authorization header value (e.g., 'Bearer TOKEN')")
@click.option("--cookie", "-c", multiple=True, help="Cookies (format: name=value)")
@click.option("--scope", default=None, help="Scope boundary URL (default: same as target)")
@click.option("--stealth", is_flag=True, help="Stealth mode: slower, randomized timing")
@click.option("--rate-limit", default=100, type=int, help="Max requests per second (default: 100)")
@click.option("--output", "-o", default=None, help="Output file (JSON format)")
@click.option("--db", default="webbreaker.db", help="Database file path (default: webbreaker.db)")
def scan(target, auth, modules, depth, threads, timeout, delay, proxy, auth_header, cookie, scope, stealth, rate_limit, output, db):
    """Run a full web application pentest scan against TARGET."""
    print_banner()

    if not auth:
        console.print("[bold red]❌ Authorization required.[/]")
        console.print("Use [bold]--auth[/] flag to confirm you have authorized access to test this target.")
        console.print("[dim]Example: webbreaker scan https://example.com --auth[/]")
        sys.exit(1)

    # Parse modules
    from core.orchestrator import ALL_MODULES
    if modules == "all":
        module_list = ALL_MODULES
    else:
        module_list = [m.strip() for m in modules.split(",")]
        invalid = set(module_list) - set(ALL_MODULES)
        if invalid:
            console.print(f"[red]Invalid modules: {', '.join(invalid)}[/]")
            console.print(f"[dim]Available: {', '.join(ALL_MODULES)}[/]")
            sys.exit(1)

    # Parse cookies
    cookies = {}
    for c in cookie:
        if "=" in c:
            name, value = c.split("=", 1)
            cookies[name.strip()] = value.strip()

    from core.config import ScanConfig
    try:
        config = ScanConfig(
            target=target,
            modules=module_list,
            depth=depth,
            threads=threads,
            timeout=timeout,
            delay=delay if delay > 0 else (0.5 if stealth else 0.0),
            proxy=proxy,
            auth_header=auth_header,
            cookies=cookies if cookies else None,
            scope=scope,
            authorized=True,
            stealth=stealth,
            rate_limit=max(5, rate_limit // 5) if stealth else rate_limit,
        )
    except PermissionError as e:
        console.print(f"[red]{e}[/]")
        sys.exit(1)

    # Run scan
    from core.orchestrator import ScanOrchestrator
    orchestrator = ScanOrchestrator(config, db_path=db)

    try:
        findings = asyncio.run(orchestrator.run(module_list))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/]")
        findings = orchestrator.findings
    finally:
        orchestrator.close()

    # Output results
    if output:
        results = {
            "scan_id": orchestrator.scan_id,
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        if output == "-":
            import sys
            json.dump(results, sys.stdout, indent=2, default=str)
            sys.stdout.write("\n")
            console.print("\n[green]Results written to stdout[/]")
        else:
            with open(output, "w") as f:
                json.dump(results, f, indent=2, default=str)
            console.print(f"\n[green]Results saved to {output}[/]")

    # Exit code based on findings
    critical = sum(1 for f in findings if f.severity.value == "CRITICAL")
    high = sum(1 for f in findings if f.severity.value == "HIGH")
    if critical > 0:
        sys.exit(2)
    elif high > 0:
        sys.exit(1)
    else:
        sys.exit(0)


@cli.command()
@click.argument("target")
@click.option("--auth", is_flag=True, required=True, help="Confirm authorized testing")
def fingerprint(target, auth):
    """Quick technology fingerprint of TARGET (no active scanning)."""
    print_banner()
    from core.config import ScanConfig
    from core.recon import ReconScanner

    config = ScanConfig(target=target, authorized=True)
    recon = ReconScanner(config)
    result = recon.fingerprint(target)

    table = Table(title=f"🔍 Technology Fingerprint: {target}")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Status Code", str(result.get("status_code", "N/A")))
    table.add_row("Server", result.get("server", "N/A"))
    table.add_row("Content-Type", result.get("content_type", "N/A"))
    table.add_row("Content Length", str(result.get("content_length", "N/A")))
    table.add_row("Technologies", ", ".join(result.get("tech", [])) or "None detected")

    console.print(table)


@cli.command()
@click.option("--db", default="webbreaker.db", help="Database file path")
def scans(db):
    """List all previous scans."""
    from core.database import Database
    database = Database(db)
    database.connect()

    scan_list = database.list_scans()
    if not scan_list:
        console.print("[dim]No scans found.[/]")
        database.close()
        return

    table = Table(title="📋 Scan History")
    table.add_column("ID", style="bold")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    table.add_column("Started")

    for s in scan_list:
        status_color = "green" if s["status"] == "completed" else "yellow"
        table.add_row(
            s["id"], s["target"],
            f"[{status_color}]{s['status']}[/{status_color}]",
            str(s["findings_count"]),
            s["started_at"][:19],
        )

    console.print(table)
    database.close()


@cli.command()
@click.argument("scan_id")
@click.option("--severity", "-s", default=None, help="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
@click.option("--db", default="webbreaker.db", help="Database file path")
def findings(scan_id, severity, db):
    """View findings for a specific scan."""
    from core.database import Database
    database = Database(db)
    database.connect()

    finding_list = database.get_findings(scan_id, severity=severity)
    if not finding_list:
        console.print("[dim]No findings found.[/]")
        database.close()
        return

    colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "green", "INFO": "dim"}
    table = Table(title=f"🔍 Findings for Scan {scan_id}")
    table.add_column("Severity", style="bold")
    table.add_column("Type")
    table.add_column("URL")
    table.add_column("Parameter")
    table.add_column("Evidence", max_width=50)

    for f in finding_list:
        color = colors.get(f["severity"], "white")
        table.add_row(
            f"[{color}]{f['severity']}[/{color}]",
            f["type"], f["url"], f["parameter"],
            f["evidence"][:50],
        )

    console.print(table)
    database.close()


@cli.command()
@click.argument("scan_id")
@click.option("--db", default="webbreaker.db", help="Database file path")
def report(scan_id, db):
    """Generate a summary report for a scan."""
    from core.database import Database
    database = Database(db)
    database.connect()

    scan_info = database.get_scan(scan_id)
    if not scan_info:
        console.print(f"[red]Scan {scan_id} not found.[/]")
        database.close()
        return

    findings_list = database.get_findings(scan_id)
    stats = database.get_stats(scan_id)

    console.print(Panel(
        f"[bold]Scan ID:[/] {scan_id}\n"
        f"[bold]Target:[/] {scan_info['target']}\n"
        f"[bold]Status:[/] {scan_info['status']}\n"
        f"[bold]Started:[/] {scan_info['started_at']}\n"
        f"[bold]Completed:[/] {scan_info.get('completed_at', 'N/A')}",
        title="📊 Scan Report",
        border_style="blue",
    ))

    console.print(f"\n[bold]Total Findings:[/] {stats['total_findings']}")
    if stats["by_severity"]:
        for sev, count in sorted(stats["by_severity"].items()):
            console.print(f"  {sev}: {count}")
    if stats["by_type"]:
        console.print("\n[bold]By Type:[/]")
        for t, count in sorted(stats["by_type"].items(), key=lambda x: -x[1]):
            console.print(f"  {t}: {count}")

    console.print(f"\n[bold]URLs Discovered:[/] {stats['urls_discovered']}")

    database.close()


@cli.command()
@click.argument("scan_id")
@click.option("--confirm", is_flag=True, help="Confirm deletion")
@click.option("--db", default="webbreaker.db", help="Database file path")
def delete(scan_id, confirm, db):
    """Delete a scan and all its data."""
    if not confirm:
        console.print("[yellow]Use --confirm to permanently delete scan data.[/]")
        return

    from core.database import Database
    database = Database(db)
    database.connect()
    database.delete_scan(scan_id)
    console.print(f"[green]Scan {scan_id} deleted.[/]")
    database.close()


if __name__ == "__main__":
    cli()