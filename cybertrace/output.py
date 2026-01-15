"""Output formatting for CyberTrace results."""

import json
from datetime import datetime
from typing import Any, Dict, Optional

from .modules.base import ModuleResult


def format_json(result: ModuleResult, indent: int = 2) -> str:
    """Format result as JSON string."""
    return json.dumps(result.to_dict(), indent=indent, default=str)


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
    
    # Source results
    lines.append(" SOURCE RESULTS ".center(width, "-"))
    lines.append("-" * width)
    
    for source_name, source_result in result.sources.items():
        status = "✓" if source_result.success else "✗"
        lines.append(f"  [{status}] {source_name}")
        
        if source_result.error:
            lines.append(f"      Error: {source_result.error}")
        elif source_result.data:
            # Show key findings
            for key, value in list(source_result.data.items())[:5]:
                if value is not None:
                    # Truncate long values
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
    """Save result to file."""
    if format == 'json':
        content = format_json(result)
    else:
        content = format_table(result)
    
    with open(filepath, 'w') as f:
        f.write(content)


def print_result(result: ModuleResult, format: str = 'table') -> None:
    """Print result to console."""
    if format == 'json':
        print(format_json(result))
    elif format == 'rich':
        format_rich(result)
    else:
        print(format_table(result))
