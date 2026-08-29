"""CyberTrace CLI - Multi-Layer OSINT Investigation Tool."""

import asyncio
import sys
from typing import Optional

import click

from .config import config
from .detector import chain_caveat, detect_input_type, normalize_input
from .modules import get_module, list_modules, resolve_module_for_target, TYPE_TO_MODULE
from .output import print_result, save_result
from .safety import is_blocked_query

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
    if is_blocked_query(target):
        click.echo("[!] Target refused: names prohibited content (CSAM/gore). "
                   "Not searched, nothing stored.", err=True)
        sys.exit(2)

    module, normalized, specific_type, module_type = resolve_module_for_target(target, input_type)
    if input_type == 'auto' and not quiet:
        click.echo(f"[*] Detected type: {specific_type} → module: {module_type}", err=True)
    if normalized != target and not quiet:
        click.echo(f"[*] Normalized: {target} → {normalized}", err=True)
    if not module:
        # An unsupported chain is refused BY NAME. It used to fall through to
        # `username` and be swept across 3000+ social sites, then report
        # nothing found -- which reads as a cleared wallet instead of a wallet
        # nobody looked at.
        caveat = chain_caveat(specific_type)
        if caveat:
            click.echo(f"[!] {caveat}", err=True)
            click.echo("[!] Supported chains: Bitcoin, Ethereum, TRON. Re-run with "
                       "--type username only if this really is a username.", err=True)
        else:
            click.echo(f"[!] No module available for type: {module_type}", err=True)
            click.echo(f"[!] Available modules: {', '.join(list_modules().keys())}", err=True)
        sys.exit(1)

    module.show_progress = not quiet
    if not quiet:
        click.echo(f"[*] Using module: {module.name}", err=True)
        click.echo(f"[*] Searching...", err=True)

    # Run search
    try:
        result = asyncio.run(_run_search(
            module, normalized, deep=deep, tor=tor, timeout=timeout, target_type=specific_type))
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
@click.argument('result_files', nargs=-1, required=False,
                type=click.Path(exists=True, dir_okay=False))
@click.option('--output', '-o', 'output_format', default='table',
              type=click.Choice(['table', 'json']), help='Output format')
@click.option('--db', 'db_path', type=click.Path(dir_okay=False),
              help='Correlate through a persistent evidence store (M5 engine)')
@click.option('--html', 'html_path', type=click.Path(dir_okay=False),
              help='Also write the evidence graph to an interactive HTML file')
@click.option('--dossier', 'dossier_path', type=click.Path(dir_okay=False),
              help='Also write the candidate case file (evidence, timeline, objections)')
def correlate(result_files, output_format: str, db_path: Optional[str],
              html_path: Optional[str], dossier_path: Optional[str]):
    """
    Correlate saved investigation results across markets.

    Investigate several onions with --save, then fold them into one evidence
    store and run the full correlation engine: ranked dossiers with evidence
    chains, successor hypotheses, and the clone findings that contradict them.

    Without --db the store is in-memory and discarded when the command exits.
    With --db it persists to disk, so later runs correlate against everything
    ingested before.

    \b
      cybertrace search "a.onion" --save a.json
      cybertrace search "b.onion" --save b.json
      cybertrace correlate a.json b.json
      cybertrace correlate a.json b.json --db case.db --html case.html
      cybertrace correlate --db case.db --dossier case.html
    """
    if (html_path or dossier_path) and not db_path:
        raise click.UsageError(
            "--html/--dossier need --db: both are rendered from the store")
    if not result_files and not db_path:
        raise click.UsageError(
            "need RESULT_FILES, or --db to re-render an existing store")
    _correlate_store(result_files, output_format, db_path or ':memory:', html_path, dossier_path)


def _correlate_store(result_files, output_format: str, db_path: str,
                     html_path: Optional[str] = None,
                     dossier_path: Optional[str] = None) -> None:
    """Ingest saved results into the evidence store, then run the M5 engine."""
    import json
    from . import memory
    from .correlate import render_dossier_html, render_html, render_markdown, run_correlation
    from .evidence import EvidenceStore, ingest

    with EvidenceStore(db_path) as store:
        target_urls = []
        for path in result_files:
            try:
                with open(path) as fh:
                    payload = json.load(fh)
                ingest(payload, store)
            except (json.JSONDecodeError, OSError) as e:
                click.echo(f"[!] Skipping {path}: {e}", err=True)
                continue
            if payload.get('target'):
                target_urls.append(payload['target'])
        target_urls = list(dict.fromkeys(target_urls))  # de-dup, keep first-seen order

        # Case history is snapshotted BEFORE this call's own run_correlation()
        # writes new rows to `candidates` below -- otherwise every candidate
        # this very pass finds would immediately cite itself as "prior" case
        # history, which is not history.
        case_history = {url: memory.case_history(store, url) for url in target_urls}

        results = run_correlation(store)

        # Historical memory: a retrieval pass over the same store, never a
        # second correlation engine. See memory.py's module docstring for the
        # EXACT/CONTEXTUAL/PRIOR_REFERENCE/PRIOR_CASE/RELATED boundary and why
        # none of it can assert SAME_OPERATOR on its own.
        memory_hits = {}
        for url in target_urls:
            matches = memory.historical_matches(store, url)
            references = memory.prior_references(store, url)
            related = memory.relationship_context(store, url)
            patterns = memory.pattern_overlap(store, url)
            cases = case_history[url]
            if any((matches, references, cases, related, patterns)):
                memory_hits[url] = {'matches': matches, 'references': references,
                                    'cases': cases, 'related': related, 'patterns': patterns}

        if output_format == 'json':
            payload_out = dict(results)
            payload_out['memory'] = memory_hits
            click.echo(json.dumps(payload_out, indent=2, default=str))
        else:
            click.echo(render_markdown(results['dossiers'], results))
            for url, hit in memory_hits.items():
                click.echo("\n".join(memory.render_markdown(
                    url, hit['matches'], hit['references'],
                    cases=hit['cases'], related=hit['related'], patterns=hit['patterns'])))

        if html_path:
            render_html(store, html_path, results)
            click.echo(f"\n[+] Evidence graph written to {html_path}", err=True)
        if dossier_path:
            render_dossier_html(results, dossier_path)
            click.echo(f"[+] Case file written to {dossier_path}", err=True)


@cli.command()
@click.option('--db', 'db_path', required=True, type=click.Path(exists=True, dir_okay=False),
              help='Evidence store to re-check')
@click.option('--target', 'targets', multiple=True,
              help='Only re-check these onions (default: every target in the store)')
@click.option('--discover', is_flag=True,
              help='Also list directory services not yet in the store')
@click.option('--output', '-o', 'output_format', default='table',
              type=click.Choice(['table', 'json']), help='Output format')
@click.option('--dossier', 'dossier_path', type=click.Path(dir_okay=False),
              help='Rewrite the case file after re-correlating')
@click.option('--deep', is_flag=True,
              help='Re-check wallets with a deeper transaction sample (see search --deep)')
def watch(db_path: str, targets, discover: bool, output_format: str,
          dossier_path: Optional[str], deep: bool):
    """
    Re-visit every target in a case and report what changed.

    Each onion target is fetched again and each wallet address already
    enriched in this case is re-searched; every capture is chained to its own
    previous one and the result is re-correlated. A site that stops answering
    is recorded as dark with its own hashed snapshot — that is what lets a
    later relaunch read as a successor rather than as two unrelated markets. A
    wallet that newly reaches a VASP, or whose nearest one changed, is
    reported the same way a new candidate is.

    \b
      cybertrace watch --db case.db
      cybertrace watch --db case.db --discover --dossier case.html
    """
    import json
    from pathlib import Path
    from .correlate import wallet_exchange_paths
    from .evidence import EvidenceStore
    from .monitor import run_watch

    with EvidenceStore(db_path) as store:
        report = run_watch(store, urls=list(targets) or None, discover=discover,
                           case_id=Path(db_path).stem, deep=deep)

        if output_format == 'json':
            click.echo(json.dumps(report, indent=2, default=str))
        else:
            click.echo(f"\nRe-checked {len(report['checked'])} target(s) and "
                       f"{len(report['wallets_checked'])} wallet(s) "
                       f"at {report['checked_at']}\n")
            for row in report['checked']:
                colour = {'DARK': 'red', 'CHANGED': 'yellow',
                          'BACK_UP': 'green'}.get(row['status'], None)
                status = click.style(f"{row['status']:<9}", fg=colour)
                detail = row.get('title') or row.get('error') or ''
                click.echo(f"  {status} {row['url'][:56]}  {detail[:60]}")
            for row in report['wallets_checked']:
                colour = {'CHECK_FAILED': 'red', 'CHANGED': 'yellow'}.get(row['status'], None)
                status = click.style(f"{row['status']:<9}", fg=colour)
                click.echo(f"  {status} {row['address'][:56]}  ({row['chain']})")
            for row in report.get('deltas', []):
                click.echo(f"\n  [{row['change']}] {row['candidate_id']} "
                           f"({row['confidence']}) {row['assessment']}")
            for row in report.get('wallet_deltas', []):
                click.echo(f"\n  [WALLET-{row['change']}] {row['value']}")
            if report.get('narrative'):
                click.echo(f"\n  [ANALYST ALERT] {report['narrative']['answer']}")
            if report.get('discovered'):
                click.echo(f"\n  {len(report['discovered'])} directory service(s) "
                           f"not in this case:")
                for row in report['discovered'][:20]:
                    click.echo(f"    {row['service'][:28]:<30} {row['onion']}")
            for w in wallet_exchange_paths(store):
                click.echo(f"\n  [WALLET] {w['value']} -> {w['proximity']} "
                           f"({w['hops']} hop(s), flow {w['direction']}) -> "
                           f"{w['exchange']} [{w['attribution']}] "
                           f"(reachability {w['confidence']:.2f})")

        if dossier_path:
            from .correlate import render_dossier_html, run_correlation
            render_dossier_html(run_correlation(store), dossier_path)
            click.echo(f"\n[+] Case file rewritten: {dossier_path}", err=True)


@cli.command()
@click.argument('candidate_id')
@click.option('--db', 'db_path', required=True, type=click.Path(exists=True, dir_okay=False),
              help='Evidence store the candidate was written to')
@click.option('--outcome', required=True,
              type=click.Choice(['CONFIRMED', 'REJECTED', 'BENIGN', 'MALICIOUS', 'UNKNOWN'],
                                case_sensitive=False),
              help='What actually happened, after review')
@click.option('--note', default=None, help='Free-text rationale')
@click.option('--analyst', default=None, help='Who is recording this')
def feedback(candidate_id: str, db_path: str, outcome: str, note: Optional[str],
            analyst: Optional[str]):
    """
    Record an analyst's verdict on a candidate from a previous `correlate` run.

    candidate_id is the OP-/IN-/IP- id printed in a dossier or the correlate
    --dossier HTML. The verdict is stored against the candidate's underlying
    entity and is read back into future `correlate` runs against this store —
    a REJECTED/BENIGN call damps that entity's contribution next time,
    CONFIRMED/MALICIOUS reinforces it slightly. It never deletes or overrides
    what the engine found; it is a second, independent fact about the same
    entity.

    \b
      cybertrace feedback OP-a1b2c3d4 --db case.db --outcome confirmed
      cybertrace feedback IN-9f8e7d6c --db case.db --outcome rejected \\
          --note "shared CDN, not operator infra" --analyst jdoe
    """
    from .evidence import EvidenceStore

    with EvidenceStore(db_path) as store:
        try:
            fid = store.record_feedback(candidate_id, outcome.upper(), note=note,
                                        analyst=analyst)
        except ValueError as e:
            click.echo(f"[!] {e}", err=True)
            sys.exit(1)
        click.echo(f"[+] Recorded {outcome.upper()} for {candidate_id} ({fid})", err=True)


@cli.command('label-exchange')
@click.argument('address')
@click.option('--exchange', required=True, help='Exchange/VASP name this address belongs to')
@click.option('--db', 'db_path', required=True, type=click.Path(exists=True, dir_okay=False),
              help='Evidence store to record the label against')
@click.option('--note', default=None, help='Citation: report, filing, or how you know this')
@click.option('--analyst', default=None, help='Who is recording this')
def label_exchange_cmd(address: str, exchange: str, db_path: str,
                       note: Optional[str], analyst: Optional[str]):
    """
    Record that a Bitcoin, Ethereum, or TRON address is a known deposit/hot-
    wallet address for an exchange, from an analyst's own knowledge — never
    inferred by CyberTrace.

    This is the only way an EXCHANGE_DEPOSIT edge is created. Once recorded,
    `correlate`/`watch` report the shortest reachable hop count from any traced
    wallet in this case to the nearest labeled address — reachability, not an
    attribution the engine makes on its own.

    \b
      cybertrace label-exchange bc1q... --exchange "Exchange X" --db case.db \\
          --note "publicly documented cold wallet" --analyst jdoe
    """
    from .evidence import EvidenceStore, label_exchange

    with EvidenceStore(db_path) as store:
        rel_id = label_exchange(store, address, exchange, analyst=analyst, note=note)
        if rel_id is None:
            click.echo(f"[!] {address!r} is not a valid Bitcoin, Ethereum, or "
                      f"TRON address", err=True)
            sys.exit(1)
        click.echo(f"[+] Recorded {address} as {exchange} ({rel_id})", err=True)


@cli.command('trace-wallet')
@click.argument('address')
@click.option('--db', 'db_path', required=True, type=click.Path(exists=True, dir_okay=False),
              help='Evidence store to trace through')
@click.option('--max-hops', default=4, show_default=True,
              help='Furthest layering depth to search for a labeled exchange')
@click.option('--output', '-o', 'output_format', default='table',
              type=click.Choice(['table', 'json']), help='Output format')
def trace_wallet_cmd(address: str, db_path: str, max_hops: int, output_format: str):
    """
    Trace a wallet already searched into this case: its path (if any) to the
    nearest VASP-attributed address, and every third-party flag already on
    record for each address along that path.

    The endpoint is attributed ANALYST_ASSERTED (label-exchange, a human's
    cited claim), REGULATORY_ATTESTED (an OFAC SDN digital-currency-address
    record, read offline -- not always a VASP, some designated parties are a
    market or a mixer), VASP_DISCLOSED (the VASP's own verified published
    wallet list), or TAG_ATTESTED (a public GraphSense tagpack entry
    read offline) -- none verified by CyberTrace and none written as an
    EXCHANGE_DEPOSIT edge. Proximity is AT_VASP / DIRECT / INDIRECT and fund
    flow is TO_VASP / FROM_VASP / UNKNOWN — UNKNOWN means the capture recorded
    that a transaction happened, not which way value moved.

    Reports findings only — no risk score. Each flag names the address and
    the evidence it came from; label-exchange and search results feed this,
    correlate never invents new ones here.

    \b
      cybertrace trace-wallet bc1q... --db case.db
    """
    from .correlate import wallet_trace_report
    from .evidence import EvidenceStore

    with EvidenceStore(db_path) as store:
        report = wallet_trace_report(store, address, max_hops=max_hops)

    if report is None:
        click.echo(f"[!] {address!r} was never searched into this case", err=True)
        sys.exit(1)

    if output_format == 'json':
        import json as _json
        click.echo(_json.dumps(report, indent=2))
        return

    click.echo(f"Wallet: {report['address']}")
    if len(report['path']) > 1:
        click.echo("Path: " + " -> ".join(report['path']))
    if report['exchange']:
        click.echo(f"Nearest VASP: {report['exchange']}")
        click.echo(f"  proximity:   {report['proximity']} ({report['hops']} hop(s))")
        click.echo(f"  attribution: {report['attribution']} "
                  f"({report['attribution_source']})")
        click.echo(f"  fund flow:   {report['direction']}")
        click.echo(f"  reachability confidence: {report['exchange_confidence']:.2f} "
                  f"(hop decay, not a probability)")
    else:
        click.echo(f"Nearest VASP: none found within {max_hops} hop(s)")
    if report['flags']:
        click.echo("Flags:")
        for flag in report['flags']:
            click.echo(f"  - {flag}")
    else:
        click.echo("Flags: none on record")


@cli.command('case')
@click.option('--db', 'db_path', required=True, type=click.Path(dir_okay=False),
              help='Evidence store to show or update')
@click.option('--name', default=None, help='Set the case name')
@click.option('--status', type=click.Choice(['open', 'closed', 'archived'], case_sensitive=False),
              default=None, help='Set the case status')
@click.option('--note', default=None, help='Append an analyst note to the case')
@click.option('--analyst', default=None, help='Who is recording the note')
@click.option('--output', '-o', 'output_format', default='table',
              type=click.Choice(['table', 'json']), help='Output format')
def case_cmd(db_path: str, name: Optional[str], status: Optional[str], note: Optional[str],
            analyst: Optional[str], output_format: str):
    """
    Show or update case-level metadata for an evidence store.

    A `--db` file is already one investigation; this names it, tracks its
    status, and holds analyst notes that aren't about any single candidate.
    With no options, prints the case summary: name, status, targets, notes.

    \b
      cybertrace case --db case.db
      cybertrace case --db case.db --name "Market X takedown" --status open
      cybertrace case --db case.db --note "confirmed with legal" --analyst jdoe
    """
    import json

    from .evidence import EvidenceStore

    with EvidenceStore(db_path) as store:
        if name or status:
            try:
                store.update_case(name=name, status=status.upper() if status else None)
            except ValueError as e:
                click.echo(f"[!] {e}", err=True)
                sys.exit(1)
        if note:
            store.add_case_note(note, analyst=analyst)

        info = store.case_info()
        notes = [dict(n) for n in store.case_notes()]
        targets = [dict(t) for t in store._all(
            "SELECT url, kind, active FROM targets ORDER BY first_seen")]

        if output_format == 'json':
            click.echo(json.dumps({**info, 'targets': targets, 'notes': notes},
                                  indent=2, default=str))
            return

        click.echo(f"\nCase {info.get('case_id')}  [{info.get('status')}]")
        if info.get('name'):
            click.echo(f"  {info['name']}")
        click.echo(f"  created {info.get('created_at')}  updated {info.get('updated_at')}")
        click.echo(f"\n  {len(targets)} target(s):")
        for t in targets:
            mark = 'active' if t['active'] else 'dark'
            click.echo(f"    [{mark:6}] {t['url']} ({t['kind']})")
        if notes:
            click.echo("\n  Notes:")
            for n in notes:
                who = f" — {n['analyst']}" if n.get('analyst') else ''
                click.echo(f"    {n['recorded_at']}  {n['note']}{who}")


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
@click.argument('address')
@click.option('--output', '-o', default='table', type=click.Choice(['table', 'json', 'rich']))
def tron(address: str, output: str):
    """Search for a TRON (TRX) address."""
    ctx = click.get_current_context()
    ctx.invoke(search, target=address, input_type='tron', output_format=output)


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
