"""CyberTrace CLI - Multi-Layer OSINT Investigation Tool."""

import asyncio
import sys
from typing import Optional

import click

from .config import config
from .detector import detect_input_type, normalize_input
from .modules import get_module, list_modules, TYPE_TO_MODULE
from .output import print_result, save_result, format_operator_candidates

LOGO = r"""
   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ████████╗██████╗  █████╗  ██████╗███████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝   ██║   ██████╔╝███████║██║     █████╗
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗   ██║   ██╔══██╗██╔══██║██║     ██╔══╝
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗███████╗
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝"""


_banner_shown = False


def show_banner() -> None:
    """
    Clear the screen and print the banner, giving each run a clean workspace.

    Interactive terminals only. When stdout is redirected — piping JSON into a
    file or through jq — the screen is left alone and nothing is drawn, and the
    banner is written to stderr regardless so it can never contaminate captured
    results.

    Guarded against running twice: help output and the group callback can both
    reach here in one invocation, and a second clear would wipe the first.
    """
    global _banner_shown
    if _banner_shown or not sys.stdout.isatty():
        return
    # -q/--quiet is defined on the subcommand, so Click hasn't parsed it yet at
    # group level; read argv directly rather than plumbing state through.
    if {'-q', '--quiet'}.intersection(sys.argv):
        return

    _banner_shown = True
    click.clear()
    click.echo(click.style(LOGO, fg='cyan', bold=True), err=True)
    click.echo(click.style(
        "  🔎 Multi-Layer OSINT Investigation Tool  ·  Surface · Deep · Dark",
        dim=True), err=True)
    click.echo(click.style(
        "\n  ────────────────⟡  A N U B H A V   M O H A N D A S  ⟡────────────────\n",
        fg=214, bold=True), err=True)


class ColorFormatter(click.HelpFormatter):
    """Help formatter that tints section headings and the name column."""

    def write_heading(self, heading: str) -> None:
        super().write_heading(click.style(heading, fg='cyan', bold=True))

    def write_dl(self, rows, *args, **kwargs) -> None:
        # Click measures these columns with term_len(), which strips ANSI first,
        # so styling the names here does not break alignment.
        super().write_dl(
            [(click.style(name, fg=214, bold=True), help_) for name, help_ in rows],
            *args, **kwargs,
        )

    def write_usage(self, prog: str, args: str = '', prefix=None) -> None:
        super().write_usage(click.style(prog, fg='green', bold=True), args, prefix)


class ColorContext(click.Context):
    def make_formatter(self) -> ColorFormatter:
        return ColorFormatter(width=self.terminal_width,
                              max_width=self.max_content_width)


class BannerGroup(click.Group):
    """Group whose help output carries the banner and CyberTrace colours."""

    context_class = ColorContext

    def format_help(self, ctx, formatter) -> None:
        # Bare `cybertrace` and `cybertrace --help` never reach the group
        # callback — Click prints help and exits during parsing — so the banner
        # has to be hooked here to appear at all.
        show_banner()
        super().format_help(ctx, formatter)


@click.group(cls=BannerGroup)
@click.version_option(version='1.0.0', prog_name='CyberTrace')
def cli():
    """
    CyberTrace - Multi-Layer OSINT Investigation Tool

    Search across Surface Web, Deep Web, and Dark Web simultaneously.

    Examples:

    \b
      cybertrace search "user@example.com"
      cybertrace search "hackerman123" --type username
      cybertrace search "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" --output json
      cybertrace search "example.com" --save report.json
      cybertrace username torvalds
    """
    show_banner()


@cli.command()
@click.argument('target')
@click.option('--type', '-t', 'input_type', default='auto',
              help='Target type (auto, email, phone, username, domain, bitcoin, indian)')
@click.option('--output', '-o', 'output_format', default='table',
              type=click.Choice(['table', 'json', 'rich']),
              help='Output format')
@click.option('--save', '-s', 'save_path', default=None,
              help='Save results to file')
@click.option('--deep', is_flag=True, help='Enable deep scan (more sources)')
@click.option('--tor', is_flag=True, help='Include direct Tor searches')
@click.option('--timeout', default=30, help='Timeout per source in seconds')
@click.option('--quiet', '-q', is_flag=True, help='Suppress progress output')
def search(target: str, input_type: str, output_format: str, save_path: Optional[str],
           deep: bool, tor: bool, timeout: int, quiet: bool):
    """
    Search for TARGET across all available sources.
    
    TARGET can be an email, phone, username, domain, Bitcoin address, etc.
    The type is auto-detected if not specified.
    """
    # Detect input type
    if input_type == 'auto':
        specific_type, module_type = detect_input_type(target)
        if not quiet:
            click.echo(f"[*] Detected type: {specific_type} → module: {module_type}", err=True)
    else:
        module_type = input_type
        specific_type = input_type
    
    # Normalize input
    normalized = normalize_input(target, module_type)
    if normalized != target and not quiet:
        click.echo(f"[*] Normalized: {target} → {normalized}", err=True)
    
    # Get module
    module = get_module(module_type)
    if not module:
        click.echo(f"[!] No module available for type: {module_type}", err=True)
        click.echo(f"[!] Available modules: {', '.join(list_modules().keys())}", err=True)
        sys.exit(1)
    
    if not quiet:
        click.echo(f"[*] Using module: {module.name}", err=True)
        click.echo(f"[*] Searching...", err=True)
    
    # Run search
    try:
        result = asyncio.run(_run_search(module, normalized, deep=deep, tor=tor, timeout=timeout))
    except KeyboardInterrupt:
        click.echo("\n[!] Search interrupted", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"[!] Error during search: {e}", err=True)
        sys.exit(1)
    
    # Output results
    print_result(result, format=output_format)
    
    # Save if requested
    if save_path:
        save_result(result, save_path, format='json')
        click.echo(f"\n[+] Results saved to: {save_path}", err=True)


async def _run_search(module, target: str, **options):
    """Run module search in async context."""
    async with module:
        return await module.search(target, **options)


@cli.command()
@click.argument('result_files', nargs=-1, required=True,
                type=click.Path(exists=True, dir_okay=False))
@click.option('--output', '-o', 'output_format', default='table',
              type=click.Choice(['table', 'json']), help='Output format')
def correlate(result_files, output_format: str):
    """
    Correlate saved investigation results across markets.

    Investigate several onions with --save, then fold them into one evidence
    graph. Artifacts (PGP key, crypto address, handle) reused across markets are
    surfaced as ranked operator candidates.

    \b
      cybertrace search "a.onion" --save a.json
      cybertrace search "b.onion" --save b.json
      cybertrace correlate a.json b.json
    """
    import json
    from .graph import EvidenceGraph, build_graph_from_dict, correlate as run_correlate

    graph = EvidenceGraph()
    for path in result_files:
        try:
            with open(path) as fh:
                build_graph_from_dict(json.load(fh), graph)
        except (json.JSONDecodeError, OSError) as e:
            click.echo(f"[!] Skipping {path}: {e}", err=True)

    corr = run_correlate(graph)
    if output_format == 'json':
        click.echo(json.dumps({'graph': graph.to_dict(), **corr}, indent=2, default=str))
    else:
        click.echo(format_operator_candidates(corr, graph))


@cli.command('config')
@click.option('--check', is_flag=True, help='Check API key status')
@click.option('--show', is_flag=True, help='Show current configuration')
def config_cmd(check: bool, show: bool):
    """Check and display configuration status."""
    if check or show:
        config.print_status()
    else:
        click.echo("Use --check or --show to view configuration")


@cli.command('modules')
def modules_cmd():
    """List available modules."""
    click.echo("\nAvailable Modules:\n")
    
    for name, description in list_modules().items():
        click.echo(f"  {name:15} - {description}")
    
    click.echo("\nInput Type Mappings:\n")
    
    # Group by module
    module_inputs = {}
    for input_type, module_name in TYPE_TO_MODULE.items():
        if module_name not in module_inputs:
            module_inputs[module_name] = []
        module_inputs[module_name].append(input_type)
    
    for module_name, inputs in sorted(module_inputs.items()):
        click.echo(f"  {module_name}: {', '.join(inputs)}")


# Shortcut commands for specific modules

@cli.command()
@click.argument('email')
@click.option('--output', '-o', default='table', type=click.Choice(['table', 'json', 'rich']))
def email(email: str, output: str):
    """Search for an email address."""
    ctx = click.get_current_context()
    ctx.invoke(search, target=email, input_type='email', output_format=output)


@cli.command()
@click.argument('username')
@click.option('--output', '-o', default='table', type=click.Choice(['table', 'json', 'rich']))
def username(username: str, output: str):
    """Search for a username across platforms."""
    ctx = click.get_current_context()
    ctx.invoke(search, target=username, input_type='username', output_format=output)


@cli.command()
@click.argument('domain')
@click.option('--output', '-o', default='table', type=click.Choice(['table', 'json', 'rich']))
def domain(domain: str, output: str):
    """Search for domain intelligence."""
    ctx = click.get_current_context()
    ctx.invoke(search, target=domain, input_type='domain', output_format=output)


@cli.command()
@click.argument('address')
@click.option('--output', '-o', default='table', type=click.Choice(['table', 'json', 'rich']))
def btc(address: str, output: str):
    """Search for a Bitcoin address."""
    ctx = click.get_current_context()
    ctx.invoke(search, target=address, input_type='bitcoin', output_format=output)


@cli.command()
@click.argument('target')
@click.option('--output', '-o', default='table', type=click.Choice(['table', 'json', 'rich']))
def indian(target: str, output: str):
    """Search Indian databases (vehicle, PAN, GSTIN, company)."""
    ctx = click.get_current_context()
    ctx.invoke(search, target=target, input_type='indian', output_format=output)


@cli.command()
@click.argument('number')
@click.option('--output', '-o', default='table', type=click.Choice(['table', 'json', 'rich']))
def phone(number: str, output: str):
    """Investigate a phone number (carrier, country, line type)."""
    ctx = click.get_current_context()
    ctx.invoke(search, target=number, input_type='phone', output_format=output)


@cli.command()
@click.argument('address')
@click.option('--output', '-o', default='table', type=click.Choice(['table', 'json', 'rich']))
def ip(address: str, output: str):
    """IP intelligence: geo, ASN, abuse score, open ports (Shodan)."""
    ctx = click.get_current_context()
    ctx.invoke(search, target=address, input_type='ip', output_format=output)


def main():
    """Entry point for CLI."""
    cli()


if __name__ == '__main__':
    main()
