"""Output formatting for CyberTrace results."""

import json
from datetime import datetime
from typing import Any, Dict, Optional

from .modules.base import ModuleResult


def format_json(result: ModuleResult, indent: int = 2) -> str:
    """Format result as JSON string."""
    return json.dumps(result.to_dict(), indent=indent, default=str)


def _format_operator_intel(intel: Dict[str, Any], width: int) -> list:
    """Expand the operator_intel block into readable lines. Only non-empty
    signals are shown so a hardened target stays quiet instead of noisy."""
    lines = [" OPERATOR INTELLIGENCE ".center(width, "-"), "-" * width]

    ips = intel.get('candidate_operator_ips')
    lines.append(f"  [!] Candidate operator IPs: {', '.join(ips) if ips else 'none found'}")

    if intel.get('live_url'):
        lines.append(f"  Live site:  {intel['live_url']}  ({intel.get('title') or 'no title'})")
    if intel.get('clock_skew_seconds') is not None:
        lines.append(f"  Clock skew: {intel['clock_skew_seconds']}s vs UTC")

    fp = intel.get('server_fingerprint') or {}
    if fp:
        lines.append(f"  Server:     {', '.join(f'{k}={v}' for k, v in fp.items())[:200]}")

    hosts = intel.get('clearnet_hosts_referenced') or []
    if hosts:
        lines.append(f"  Clearnet hosts referenced ({len(hosts)}):")
        for h in hosts[:15]:
            lines.append(f"      - {h}")

    for label, key in (('Emails', 'emails'), ('Analytics IDs', 'analytics_ids')):
        vals = intel.get(key) or []
        if vals:
            lines.append(f"  {label}: {', '.join(vals)}")

    crypto = intel.get('crypto') or {}
    for coin, addrs in crypto.items():
        if addrs:
            lines.append(f"  {coin.capitalize()}: {', '.join(addrs)}")

    if intel.get('pgp_key_present'):
        lines.append("  PGP key present on page: yes")

    for m in intel.get('favicon_shodan') or []:
        lines.append(
            f"  [!] Favicon match: {m.get('ip')}:{m.get('port')} "
            f"{m.get('org') or ''} {m.get('hostnames') or ''}".rstrip()
        )

    for mc in intel.get('misconfigurations') or []:
        leak = f" leaked_ips={mc['leaked_ips']}" if mc.get('leaked_ips') else ""
        lines.append(f"  Misconfig: {mc.get('path')} ({mc.get('status')}){leak}")

    lines.append("")
    lines.append("-" * width)
    return lines


def _format_pivots(pivots: list, width: int) -> list:
    """Render the operator-artifact pivots (email/crypto sub-module results)."""
    lines = [" ARTIFACT PIVOTS ".center(width, "-"), "-" * width]
    for p in pivots:
        head = f"  {p.get('type', '?')}: {p.get('target', '')}"
        if p.get('error'):
            lines.append(f"{head}  [error: {p['error']}]")
            continue
        lines.append(f"{head}  ({p.get('sources_ok', '')})")
        for k, v in list((p.get('summary') or {}).items())[:4]:
            if isinstance(v, list):
                v = f"{len(v)} items"
            elif isinstance(v, dict):
                v = f"{len(v)} entries"
            sv = str(v)
            lines.append(f"      {k}: {sv[:57] + '...' if len(sv) > 60 else sv}")
    lines.append("")
    lines.append("-" * width)
    return lines


def format_table(result: ModuleResult) -> str:
    """Format result as ASCII table."""
    lines = []
    
    # Header
    width = 70
    lines.append("=" * width)
    lines.append(f" CYBERTRACE RESULTS ".center(width, "="))
    lines.append("=" * width)
    lines.append("")
    lines.append(f"  Target:     {result.target}")
    lines.append(f"  Type:       {result.target_type}")
    lines.append(f"  Module:     {result.module}")
    lines.append(f"  Duration:   {result.duration:.2f}s")
    lines.append(f"  Sources:    {result.success_count}/{result.total_count} successful")
    lines.append("")
    lines.append("-" * width)

    # Operator intelligence — the headline for onion targets. Rendered up top
    # and fully expanded (the generic summary renderer only shows "N entries").
    intel = (result.summary or {}).get('operator_intel')
    if intel:
        lines.extend(_format_operator_intel(intel, width))

    pivots = (result.summary or {}).get('operator_pivots')
    if pivots:
        lines.extend(_format_pivots(pivots, width))

    # Source results
    lines.append(" SOURCE RESULTS ".center(width, "-"))
    lines.append("-" * width)
    
    for source_name, source_result in result.sources.items():
        status = "✓" if source_result.success else "✗"
        lines.append(f"  [{status}] {source_name}")
        
        if source_result.error:
            lines.append(f"      Error: {source_result.error}")
        elif source_result.data:
            # Show key findings — truncate before str() conversion to avoid
            # building large string representations of nested objects
            for key, value in list(source_result.data.items())[:5]:
                if value is not None:
                    if isinstance(value, str):
                        str_val = value[:47] + "..." if len(value) > 50 else value
                    else:
                        str_val = str(value)
                        if len(str_val) > 50:
                            str_val = str_val[:47] + "..."
                    lines.append(f"      {key}: {str_val}")
        lines.append("")
    
    lines.append("-" * width)
    
    # Summary
    lines.append(" SUMMARY ".center(width, "-"))
    lines.append("-" * width)
    
    if result.summary:
        for key, value in result.summary.items():
            if value is not None:
                # Format value based on type
                if isinstance(value, list):
                    if len(value) <= 3:
                        str_val = ", ".join(str(v) for v in value)
                    else:
                        str_val = f"{len(value)} items"
                elif isinstance(value, dict):
                    str_val = f"{len(value)} entries"
                else:
                    str_val = str(value)
                    if len(str_val) > 50:
                        str_val = str_val[:47] + "..."
                
                lines.append(f"  {key}: {str_val}")
    else:
        lines.append("  No summary available")
    
    lines.append("")
    lines.append("-" * width)
    
    # Related targets
    if result.related:
        lines.append(" RELATED TARGETS ".center(width, "-"))
        lines.append("-" * width)
        for related in result.related[:10]:
            lines.append(f"  → {related}")
        if len(result.related) > 10:
            lines.append(f"  ... and {len(result.related) - 10} more")
        lines.append("")
        lines.append("-" * width)
    
    lines.append("=" * width)
    
    return "\n".join(lines)


def format_rich(result: ModuleResult):
    """Format result using rich library for colored console output."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.tree import Tree
        from rich import box
    except ImportError:
        # Fallback to plain table
        print(format_table(result))
        return
    
    console = Console()
    
    # Header panel
    header = f"""
[bold cyan]Target:[/] {result.target}
[bold cyan]Type:[/] {result.target_type}
[bold cyan]Module:[/] {result.module}
[bold cyan]Duration:[/] {result.duration:.2f}s
[bold cyan]Sources:[/] {result.success_count}/{result.total_count} successful
"""
    console.print(Panel(header.strip(), title="[bold]CYBERTRACE RESULTS[/]", box=box.DOUBLE))
    
    # Source results table
    source_table = Table(title="Source Results", box=box.ROUNDED)
    source_table.add_column("Source", style="cyan")
    source_table.add_column("Status", justify="center")
    source_table.add_column("Key Findings", style="dim")
    
    for source_name, source_result in result.sources.items():
        status = "[green]✓[/]" if source_result.success else "[red]✗[/]"
        
        if source_result.error:
            findings = f"[red]{source_result.error}[/]"
        elif source_result.data:
            # Get first few key findings
            findings_list = []
            for k, v in list(source_result.data.items())[:3]:
                if v is not None:
                    str_v = str(v)[:30]
                    findings_list.append(f"{k}: {str_v}")
            findings = ", ".join(findings_list)
        else:
            findings = "-"
        
        source_table.add_row(source_name, status, findings)
    
    console.print(source_table)
    console.print()
    
    # Summary
    if result.summary:
        summary_tree = Tree("[bold]Summary[/]")
        for key, value in result.summary.items():
            if value is not None:
                if isinstance(value, list) and len(value) > 0:
                    branch = summary_tree.add(f"[cyan]{key}[/]")
                    for item in value[:5]:
                        branch.add(str(item))
                    if len(value) > 5:
                        branch.add(f"[dim]... and {len(value) - 5} more[/]")
                elif isinstance(value, dict):
                    branch = summary_tree.add(f"[cyan]{key}[/]")
                    for k, v in list(value.items())[:5]:
                        branch.add(f"{k}: {v}")
                else:
                    summary_tree.add(f"[cyan]{key}:[/] {value}")
        
        console.print(summary_tree)
        console.print()
    
    # Related targets
    if result.related:
        console.print("[bold]Related Targets:[/]")
        for related in result.related[:10]:
            console.print(f"  → {related}")
        if len(result.related) > 10:
            console.print(f"  [dim]... and {len(result.related) - 10} more[/]")


def save_result(result: ModuleResult, filepath: str, format: str = 'json') -> None:
    """Save result to file (synchronous — use save_result_async inside async code)."""
    if format == 'json':
        content = format_json(result)
    else:
        content = format_table(result)

    with open(filepath, 'w') as f:
        f.write(content)


async def save_result_async(result: ModuleResult, filepath: str, format: str = 'json') -> None:
    """Save result to file without blocking the event loop."""
    try:
        import aiofiles
        content = format_json(result) if format == 'json' else format_table(result)
        async with aiofiles.open(filepath, 'w') as f:
            await f.write(content)
    except ImportError:
        # aiofiles not installed — fall back to thread pool to avoid blocking
        import asyncio
        content = format_json(result) if format == 'json' else format_table(result)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: open(filepath, 'w').write(content))


def print_result(result: ModuleResult, format: str = 'table') -> None:
    """Print result to console."""
    if format == 'json':
        print(format_json(result))
    elif format == 'rich':
        format_rich(result)
    else:
        print(format_table(result))
