"""CyberTrace CLI - Multi-Layer OSINT Investigation Tool."""

import asyncio
import sys
from typing import Optional

import click

from .config import config
from .detector import detect_input_type, normalize_input
from .modules import get_module, list_modules, TYPE_TO_MODULE
from .output import print_result, save_result


@click.group()
@click.version_option(version='1.0.0', prog_name='CyberTrace')
def cli():
    """
    CyberTrace - Multi-Layer OSINT Investigation Tool
    
    Search across Surface Web, Deep Web, and Dark Web simultaneously.
    
    Examples:
    
        cybertrace search "user@example.com"
        
        cybertrace search "hackerman123" --type username
        
        cybertrace search "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" --output json
        
        cybertrace search "example.com" --save report.json
    """
    pass


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
            click.echo(f"[*] Detected type: {specific_type} → module: {module_type}")
    else:
        module_type = input_type
        specific_type = input_type
    
    # Normalize input
    normalized = normalize_input(target, module_type)
    if normalized != target and not quiet:
        click.echo(f"[*] Normalized: {target} → {normalized}")
    
    # Get module
    module = get_module(module_type)
    if not module:
        click.echo(f"[!] No module available for type: {module_type}", err=True)
        click.echo(f"[!] Available modules: {', '.join(list_modules().keys())}", err=True)
        sys.exit(1)
    
    if not quiet:
        click.echo(f"[*] Using module: {module.name}")
        click.echo(f"[*] Searching...")
    
    # Run search
    try:
        result = asyncio.run(_run_search(module, normalized, deep=deep, tor=tor, timeout=timeout))
    except KeyboardInterrupt:
        click.echo("\n[!] Search interrupted")
        sys.exit(1)
    except Exception as e:
        click.echo(f"[!] Error during search: {e}", err=True)
        sys.exit(1)
    
    # Output results
    print_result(result, format=output_format)
    
    # Save if requested
    if save_path:
        save_result(result, save_path, format='json')
        click.echo(f"\n[+] Results saved to: {save_path}")


async def _run_search(module, target: str, **options):
    """Run module search in async context."""
    async with module:
        return await module.search(target, **options)


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


def main():
    """Entry point for CLI."""
    cli()


if __name__ == '__main__':
    main()
