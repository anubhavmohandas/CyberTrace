"""CyberTrace CLI - Multi-Layer OSINT Investigation Tool."""

import asyncio
import sys
from typing import Optional

import click

from .config import config
from .detector import chain_caveat, detect_input_type
from .modules import get_module, list_modules, resolve_module_for_target, TYPE_TO_MODULE
from .output import print_result, save_result
from .safety import is_blocked_query

# Every chain trace-wallet/label-exchange/trace-wallet-batch accept explicitly.
# bnb/polygon must always be given by name -- a bare 0x address auto-detects
# as ethereum only (see detector.chain_caveat). solana needs no such override
# (its base58 shape auto-detects unambiguously, same as bitcoin/tron) but
# still has to be listed here or these three commands would refuse
# --chain solana outright even though correlate.py/detector.py both support
# it (Loop 38 Section 8).
_WALLET_CHAINS = ('bitcoin', 'ethereum', 'bnb', 'polygon', 'tron', 'solana')

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
              help='Target type (auto, email, phone, username, domain, bitcoin, ethereum, '
                   'bnb, polygon, tron, indian). bnb/polygon must be given explicitly -- a '
                   '0x address auto-detects as ethereum (see chain_caveat).')
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
        click.echo("[*] Searching...", err=True)

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
            except (json.JSONDecodeError, OSError, ValueError) as e:
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
        try:
            report = run_watch(store, urls=list(targets) or None, discover=discover,
                               case_id=Path(db_path).stem, deep=deep)
        except ValueError as e:
            click.echo(f"[!] {e}", err=True)
            sys.exit(1)

        if output_format == 'json':
            click.echo(json.dumps(report, indent=2, default=str))
        else:
            click.echo(f"\nRe-checked {len(report['checked'])} target(s) and "
                       f"{len(report['wallets_checked'])} wallet(s) "
                       f"at {report['checked_at']}\n")
            if report.get('data_source_status'):
                _echo_data_source_status(report['data_source_status'])
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
            for row in report.get('risk_alerts', []):
                r = row['risk']
                colour = 'red' if r['risk_level'] == 'CRITICAL' else 'yellow'
                click.echo(f"\n  [RISK ALERT] "
                           f"{click.style(r['risk_level'], fg=colour)} "
                           f"{row['value']} (score {r['risk_score']}, "
                           f"{', '.join(r['risk_categories'])})")
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


@cli.command('wallet-verdict')
@click.argument('address')
@click.option('--db', 'db_path', required=True, type=click.Path(exists=True, dir_okay=False),
              help='Evidence store the wallet was traced into')
@click.option('--outcome', required=True,
              type=click.Choice(['CONFIRMED', 'REJECTED', 'BENIGN', 'MALICIOUS', 'UNKNOWN'],
                                case_sensitive=False),
              help='What actually happened, after review')
@click.option('--note', default=None, help='Free-text rationale')
@click.option('--analyst', default=None, help='Who is recording this')
@click.option('--chain', default=None,
              type=click.Choice(_WALLET_CHAINS),
              help='Chain ADDRESS was searched on. Required for a bnb/polygon wallet -- '
                   'a 0x address otherwise resolves to ethereum only.')
def wallet_verdict_cmd(address: str, db_path: str, outcome: str, note: Optional[str],
                       analyst: Optional[str], chain: Optional[str]):
    """
    Record an analyst's verdict on a wallet already traced into this case --
    reviewed, confirmed, or dismissed -- kept apart from the automated
    wallet_role/attribution/risk fields the same way `feedback` keeps a
    candidate verdict apart from the engine's own score. Never overwrites
    that automated intelligence; it is a second, independent fact about the
    same wallet, read back into every report/GUI/Investigator surface
    alongside it.

    \b
      cybertrace wallet-verdict bc1q... --db case.db --outcome confirmed
      cybertrace wallet-verdict 0x... --chain bnb --db case.db --outcome benign \\
          --note "cleared: known merchant deposit address" --analyst jdoe
    """
    from .correlate import _TRACE_CHAIN_ETYPES
    from .evidence import EvidenceStore

    with EvidenceStore(db_path) as store:
        specific, detected_chain = detect_input_type(address)
        resolved_chain = chain or detected_chain
        if resolved_chain == 'unsupported_chain':
            click.echo(f"[!] {address!r} is not a valid Bitcoin, Ethereum, BNB Chain, "
                      f"Polygon, TRON, or Solana address", err=True)
            sys.exit(1)
        etype = _TRACE_CHAIN_ETYPES.get(resolved_chain, "BTC_ADDRESS")
        entity_id = store.find_entity(etype, address)
        if entity_id is None:
            click.echo(f"[!] {address!r} was never searched into this case", err=True)
            sys.exit(1)
        try:
            fid = store.record_wallet_feedback(entity_id, outcome.upper(), note=note,
                                               analyst=analyst)
        except ValueError as e:
            click.echo(f"[!] {e}", err=True)
            sys.exit(1)
        click.echo(f"[+] Recorded {outcome.upper()} for {address} ({fid})", err=True)


@cli.command('label-exchange')
@click.argument('address')
@click.option('--exchange', required=True, help='Exchange/VASP name this address belongs to')
@click.option('--db', 'db_path', required=True, type=click.Path(exists=True, dir_okay=False),
              help='Evidence store to record the label against')
@click.option('--note', default=None, help='Citation: report, filing, or how you know this')
@click.option('--analyst', default=None, help='Who is recording this')
@click.option('--chain', default=None,
              type=click.Choice(_WALLET_CHAINS),
              help='Chain this address is on. Required for bnb/polygon -- a 0x address '
                   'auto-detects as ethereum otherwise (see chain_caveat).')
def label_exchange_cmd(address: str, exchange: str, db_path: str,
                       note: Optional[str], analyst: Optional[str], chain: Optional[str]):
    """
    Record that a Bitcoin, Ethereum, BNB Chain, Polygon, TRON, or Solana
    address is a known deposit/hot-wallet address for an exchange, from an
    analyst's own knowledge — never inferred by CyberTrace.

    This is the only way an EXCHANGE_DEPOSIT edge is created. Once recorded,
    `correlate`/`watch` report the shortest reachable hop count from any traced
    wallet in this case to the nearest labeled address — reachability, not an
    attribution the engine makes on its own.

    \b
      cybertrace label-exchange bc1q... --exchange "Exchange X" --db case.db \\
          --note "publicly documented cold wallet" --analyst jdoe
      cybertrace label-exchange 0x... --exchange "Exchange X" --chain bnb --db case.db
    """
    from .evidence import EvidenceStore, label_exchange

    with EvidenceStore(db_path) as store:
        try:
            rel_id = label_exchange(store, address, exchange, analyst=analyst, note=note, chain=chain)
        except ValueError as e:
            click.echo(f"[!] {e}", err=True)
            sys.exit(1)
        if rel_id is None:
            click.echo(f"[!] {address!r} is not a valid Bitcoin, Ethereum, BNB Chain, "
                      f"Polygon, TRON, or Solana address", err=True)
            sys.exit(1)
        click.echo(f"[+] Recorded {address} as {exchange} ({rel_id})", err=True)


@cli.command('trace-cross-chain')
@click.argument('address')
@click.option('--db', 'db_path', required=True, type=click.Path(dir_okay=False),
              help='Evidence store to record any found links into')
@click.option('--output', '-o', 'output_format', default='table',
              type=click.Choice(['table', 'json']), help='Output format')
def trace_cross_chain_cmd(address: str, db_path: str, output_format: str):
    """
    Query live Wormholescan (bridge transfers), THORChain Midgard
    (cross-chain swaps), Across Protocol (bridge deposits) and LI.FI
    (cross-chain aggregator transfers) for ADDRESS, and record any real
    transaction-level cross-chain links found.

    Distinct from `correlate`'s own cross-chain links: those read the local
    OFAC/VASP-disclosure/GraphSense corpora for a SHARED designation across
    chains. This reads a live third party's own transaction record -- never
    treated as proof the source and destination addresses share a
    controller, and never given an invented confidence number (neither
    source publishes one). See cybertrace.modules.cross_chain_module.

    \b
      cybertrace trace-cross-chain 0x... --db case.db
    """
    import asyncio
    import json as _json

    from .evidence import EvidenceStore
    from .modules.cross_chain_module import AcrossModule, LifiModule, ThorchainModule, WormholeModule

    async def _fetch() -> list:
        links = []
        for module_cls in (WormholeModule, ThorchainModule, AcrossModule, LifiModule):
            async with module_cls() as m:
                links += (await m.search(address)).summary.get("transaction_cross_chain_links", [])
        return links

    with EvidenceStore(db_path) as store:
        try:
            store._require_open()
        except ValueError as e:
            click.echo(f"[!] {e}", err=True)
            sys.exit(1)

        links = asyncio.run(_fetch())
        for link in links:
            store.record_cross_chain_tx_link(link)

    if output_format == 'json':
        click.echo(_json.dumps(links, indent=2))
        return
    if not links:
        click.echo(f"[i] No live bridge/swap activity found for {address!r} via "
                  f"Wormholescan or THORChain Midgard.")
        return
    for link in links:
        dest = f"{link['dest_address']} ({link['dest_chain']})" if link.get('dest_address') \
            else "destination not supplied"
        click.echo(f"  [{link['mechanism']}] {link['source_address']} ({link['source_chain']}) "
                  f"-> {dest} via {link['source_api']}"
                  + (f" ({link['status']})" if link.get('status') else "")
                  + f" [ref: {link['evidence_ref']}]")
    click.echo(f"\n[+] Recorded {len(links)} link(s)", err=True)


@cli.command('trace-wallet')
@click.argument('address')
@click.option('--db', 'db_path', required=True, type=click.Path(exists=True, dir_okay=False),
              help='Evidence store to trace through')
@click.option('--max-hops', default=4, show_default=True,
              help='Furthest layering depth to search for a labeled exchange')
@click.option('--output', '-o', 'output_format', default='table',
              type=click.Choice(['table', 'json']), help='Output format')
@click.option('--chain', default=None,
              type=click.Choice(_WALLET_CHAINS),
              help='Chain ADDRESS was searched on. Required to trace a bnb/polygon '
                   'wallet -- a 0x address otherwise looks up ethereum only.')
def trace_wallet_cmd(address: str, db_path: str, max_hops: int, output_format: str,
                     chain: Optional[str]):
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

    Each flag names the address and the evidence it came from; label-exchange
    and search results feed this, correlate never invents new ones here.

    A path address GraphSense tags as a mixing service, DeFi service, DeFi
    DEX, or CoinJoin service shows up as its own flag line and in
    `service_tags` — separate from, and never counted as, VASP attribution.

    A separate, explainable risk score (`risk` -- policy risk-v1, see
    cybertrace/risk.py) is also reported: a policy scale, not a probability,
    kept apart from the VASP/proximity findings above. INSUFFICIENT_EVIDENCE
    means no qualifying risk evidence was found, never an implied LOW.

    \b
      cybertrace trace-wallet bc1q... --db case.db
    """
    from .correlate import wallet_trace_report
    from .evidence import EvidenceStore

    with EvidenceStore(db_path) as store:
        report = wallet_trace_report(store, address, max_hops=max_hops, chain=chain)

    if report is None:
        click.echo(f"[!] {address!r} was never searched into this case", err=True)
        sys.exit(1)

    if output_format == 'json':
        import json as _json
        click.echo(_json.dumps(report, indent=2))
        return

    click.echo(f"Wallet: {report['address']} ({report['chain']})")
    if len(report['path']) > 1:
        click.echo("Path: " + " -> ".join(report['path']))
    if report['exchange']:
        # proximity glued onto the same line as the name (Loop 48 finding: a
        # bare "Nearest VASP: X" headline, split from proximity on the next
        # line, reads as an ownership claim to anyone who only captures this
        # one line -- e.g. a log excerpt or grep) -- same discipline
        # trace-wallet-batch's summary line and every Markdown/HTML row
        # already apply.
        click.echo(f"Nearest VASP: {report['exchange']} "
                  f"({report['proximity']}, {report['hops']} hop(s))")
        if report.get('also_attributed'):
            names = ', '.join(sorted({c['exchange'] for c in report['also_attributed']}))
            click.echo(f"  [!] ALSO attributed to (conflicting evidence on this SAME "
                      f"address, not merged): {names}", err=True)
        click.echo(f"  proximity:   {report['proximity']} ({report['hops']} hop(s))")
        click.echo(f"  attribution: {report['attribution']} "
                  f"({report['attribution_source']})")
        if report['wallet_role']:
            click.echo(f"  wallet role: {report['wallet_role']} "
                      f"(the VASP's own disclosure, not an inference)")
        click.echo(f"  fund flow:   {report['direction']}")
        if report.get('deposit_candidate'):
            click.echo("  [!] possible deposit endpoint: 1 hop, one-way flow toward the VASP "
                      "(reachability only, not proof of a customer relationship)")
        click.echo(f"  reachability confidence: {report['exchange_confidence']:.2f} "
                  f"(hop decay, not a probability)")
    else:
        click.echo(f"Nearest VASP: none found within {max_hops} hop(s)")
        _echo_vasp_candidates(report.get('vasp_candidates'))
    _echo_vasp_investigation(report.get('vasp_investigation'))
    if report['flags']:
        click.echo("Flags:")
        for flag in report['flags']:
            click.echo(f"  - {flag}")
    else:
        click.echo("Flags: none on record")

    risk = report['risk']
    if risk['risk_score'] is None:
        click.echo(f"Risk: {risk['risk_level']} ({risk['risk_policy_version']})")
    else:
        click.echo(f"Risk: {risk['risk_level']} — score {risk['risk_score']} "
                  f"({risk['risk_policy_version']}), categories: "
                  f"{', '.join(risk['risk_categories'])}")
        for reason in risk['risk_reasons']:
            click.echo(f"  - {reason}")

    _echo_data_source_status(report['data_source_status'])


def _echo_vasp_candidates(candidates: Optional[dict]) -> None:
    """Loop 45: fingerprint-based VASP candidates for a wallet with no
    reachability hit at all (correlate.unattributed_wallet_candidates) --
    HIGH/MEDIUM/LOW strength, never a percentage, and every brand named,
    never just the strongest one. Silent when there is no real signal
    either -- matches wallet_trace_report's own "None, not a claim of zero"."""
    if not candidates or not candidates.get('primary_candidate'):
        return
    click.echo("VASP candidates (fingerprint-based, no direct reachability -- "
              "see the evidence behind each):")
    click.echo(f"  {candidates['primary_candidate']} — {candidates['strength']} "
              f"({candidates['status']})")
    for sig in candidates['supporting_signals']:
        click.echo(f"    + {sig.get('detail') or sig['rule_id']} "
                  f"[{sig['attribution_source']}]")
    if candidates['also_attributed']:
        names = ', '.join(f"{c['brand']} ({c['strength']})" for c in candidates['also_attributed'])
        click.echo(f"  [!] ALSO a candidate for (conflicting evidence, not merged): {names}",
                  err=True)
    if candidates.get('behavioral_note'):
        click.echo(f"  context: {candidates['behavioral_note']} "
                  "(supporting color only, never sufficient alone)")


def _echo_vasp_investigation(vi: Optional[dict]) -> None:
    """Loop 49: the canonical VASP investigation result (see
    cybertrace/vasp_investigation.py) -- one place an investigator reads WHY
    a VASP was named and, separately, whether ownership/control is actually
    established, instead of reconstructing that from `exchange`/`attribution`/
    `proximity` by hand. Never prints an ownership claim the evidence does
    not support: Control/Ownership is always its own line."""
    if not vi:
        return
    click.echo()
    click.echo("VASP Attribution")
    click.echo("-" * 16)
    if vi['primary_vasp']:
        relationship = f"{vi['proximity']} {vi['relationship_type']}" if vi['proximity'] \
            else (vi['relationship_type'] or 'CANDIDATE EXPOSURE')
        click.echo(f"Primary VASP: {vi['primary_vasp']}")
        click.echo(f"Relationship: {relationship}")
        click.echo(f"Confidence: {vi['confidence']}")
        if vi['hops'] is not None:
            click.echo(f"Hop Count: {vi['hops']}")
        if vi['attribution_tier']:
            click.echo(f"Attribution Tier: {vi['attribution_tier']}")
        if vi['candidate_vasps']:
            click.echo(f"Alternative candidate(s): {', '.join(vi['candidate_vasps'])} "
                      f"— {vi['status']}")
    else:
        click.echo(f"Status: {vi['status']}")
    control_line = f"Control / Ownership: {vi['control_status']}"
    if vi['control_confidence']:
        control_line += f" ({vi['control_confidence']} confidence)"
    click.echo(control_line)
    if vi['regulatory_context']['designated']:
        click.echo(f"Regulatory Context: OFAC designation "
                  f"({vi['regulatory_context']['entity']})")
    for limitation in vi['limitations']:
        click.echo(f"  Limitation: {limitation}")


def _echo_data_source_status(status: dict) -> None:
    """One line, always printed: FRESH/STALE/UNAVAILABLE per offline
    attribution source this report drew on. Not gated behind a --verbose
    flag -- a "no match" reader can't tell it apart from a stale/unavailable
    corpus any other way (Loop 39 Section 4)."""
    line = ", ".join(f"{name}={state}" for name, state in status.items())
    not_fresh = [name for name, state in status.items() if state != "FRESH"]
    click.echo(f"Data sources: {line}")
    if not_fresh:
        click.echo(f"  [!] not fresh: {', '.join(not_fresh)} -- "
                  f"a 'no match' from these does not mean 'checked, clean'", err=True)


def _parse_batch_rows(path: str) -> list:
    """Parse a `trace-wallet-batch` input file: CSV with an `address` column
    and an optional `chain` column (one of _WALLET_CHAINS). `chain` left
    blank, or the column omitted entirely, lets the address's own shape
    decide bitcoin/ethereum/tron -- bnb/polygon can never be auto-detected
    (a 0x address is valid on all three EVM chains) and must be given.

    One format, not several: kept to exactly the shape the module's own
    docstring documents rather than guessing at CSV dialects or a headerless
    one-address-per-line variant nobody asked for.
    """
    import csv

    with open(path, newline='') as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or 'address' not in reader.fieldnames:
            raise click.UsageError(
                "input file needs a header row with an 'address' column "
                "(and an optional 'chain' column)")
        rows = []
        for line in reader:
            address = (line.get('address') or '').strip()
            if not address:
                continue
            chain = (line.get('chain') or '').strip().lower() or None
            rows.append({'address': address, 'chain': chain})
    return rows


async def _trace_one_wallet(address: str, chain: Optional[str], store, max_hops: int,
                            deep: bool, semaphore: 'asyncio.Semaphore') -> dict:
    """Search + ingest + trace ONE wallet -- reuses exactly what `cybertrace
    search` -> `cybertrace correlate --db` -> `cybertrace trace-wallet` already
    do one command at a time (see wallet_trace_report and evidence.ingest); the
    batch adds only the loop and the concurrency bound around this, never a
    second tracing implementation.

    Never raises: every failure mode (an unsupported/misspelled chain, an
    address whose shape no supported chain recognises, a search that raises,
    a search that comes back with nothing ingestible) becomes a `status` in
    the returned dict instead, so one bad row cannot abort the wallets
    around it.
    """
    from .correlate import wallet_trace_report
    from .evidence import ingest

    resolved_chain = chain
    if resolved_chain is None:
        specific, detected = detect_input_type(address)
        if detected not in ('bitcoin', 'ethereum', 'tron', 'solana'):
            caveat = chain_caveat(specific)
            return {'wallet': address, 'chain': None, 'status': 'invalid_address',
                    'result': None,
                    'error': caveat or f"could not detect a supported chain for {address!r}"}
        resolved_chain = detected
    elif resolved_chain not in _WALLET_CHAINS:
        return {'wallet': address, 'chain': chain, 'status': 'unsupported_chain',
                'result': None, 'error': f"unsupported chain: {chain!r}"}

    module = get_module(resolved_chain)
    if module is None:
        return {'wallet': address, 'chain': chain, 'status': 'unsupported_chain',
                'result': None, 'error': f"no module registered for chain: {resolved_chain!r}"}

    async with semaphore:
        try:
            async with module:
                search_result = await module.search(address, deep=deep, target_type=resolved_chain)
        except Exception as e:
            return {'wallet': address, 'chain': chain, 'status': 'error',
                    'result': None, 'error': str(e)}

    try:
        ingest(search_result, store)
        report = wallet_trace_report(store, address, max_hops=max_hops, chain=chain)
    except Exception as e:
        return {'wallet': address, 'chain': chain, 'status': 'error',
                'result': None, 'error': str(e)}

    if report is None:
        return {'wallet': address, 'chain': chain, 'status': 'no_data', 'result': None,
                'error': 'search produced no ingestible data for this wallet'}
    return {'wallet': address, 'chain': chain, 'status': 'ok', 'result': report, 'error': None}


async def _run_wallet_batch(rows: list, db_path: str, max_hops: int, deep: bool,
                            concurrency: int) -> list:
    """Trace every (address, chain) row in `rows` against one shared evidence
    store.

    Concurrency is bounded by `concurrency` (config.max_concurrent, an
    existing, previously-unused knob, by default) -- a semaphore around the
    network half of each wallet only; every DB write happens synchronously on
    this one coroutine's own turn, so sqlite is never touched from two tasks
    at once even though their searches overlap.

    Duplicate (address, chain) rows do the network/ingest work once and reuse
    that wallet's result for every later occurrence, marked `duplicate` --
    "no duplicate work where safe" without silently dropping the repeated row
    from the output.
    """
    from .evidence import EvidenceStore

    semaphore = asyncio.Semaphore(max(1, concurrency))
    unique_keys = list(dict.fromkeys((r['address'], r['chain']) for r in rows))

    with EvidenceStore(db_path) as store:
        outcomes = await asyncio.gather(
            *(_trace_one_wallet(addr, chain, store, max_hops, deep, semaphore)
              for addr, chain in unique_keys),
            return_exceptions=True)

    by_key = {}
    for (addr, chain), outcome in zip(unique_keys, outcomes):
        if isinstance(outcome, Exception):
            outcome = {'wallet': addr, 'chain': chain, 'status': 'error',
                      'result': None, 'error': str(outcome)}
        by_key[(addr, chain)] = outcome

    out = []
    first_seen = set()
    for row in rows:
        key = (row['address'], row['chain'])
        base = by_key[key]
        if key in first_seen:
            out.append({**base, 'status': 'duplicate'})
        else:
            first_seen.add(key)
            out.append(dict(base))
    return out


@cli.command('trace-wallet-batch')
@click.argument('input_file', type=click.Path(exists=True, dir_okay=False))
@click.option('--db', 'db_path', required=True, type=click.Path(dir_okay=False),
              help='Evidence store to search into and trace through')
@click.option('--max-hops', default=4, show_default=True,
              help='Furthest layering depth to search for a labeled exchange, per wallet')
@click.option('--concurrency', default=None, type=int,
              help='Wallets searched at once (default: config.max_concurrent / MAX_CONCURRENT)')
@click.option('--deep', is_flag=True, help='Widen the transaction-history sample per wallet')
@click.option('--output', '-o', 'output_format', default='table',
              type=click.Choice(['table', 'json']), help='Output format')
def trace_wallet_batch_cmd(input_file: str, db_path: str, max_hops: int,
                           concurrency: Optional[int], deep: bool, output_format: str):
    """
    Search and trace many wallets in one run: bounded-concurrency sibling of
    `search` + `correlate --db` + `trace-wallet` run once per address in
    INPUT_FILE, all against one shared evidence store.

    INPUT_FILE is a CSV with an `address` column and an optional `chain`
    column (bitcoin/ethereum/bnb/polygon/tron/solana). A blank/omitted
    `chain` lets the address decide bitcoin/ethereum/tron/solana; bnb/polygon
    must be given explicitly -- same rule as `trace-wallet --chain`.

    \b
      cybertrace trace-wallet-batch wallets.csv --db case.db

    wallets.csv:

    \b
      address,chain
      bc1q...,bitcoin
      0x...,ethereum
      T...,tron
      0x...,bnb

    One wallet's search/API failure does not abort the others. Each result
    carries `status`: ok, duplicate, invalid_address, unsupported_chain,
    no_data, or error -- never silently dropped. `result` is exactly a
    `trace-wallet` report (evidence ids, VASP attribution, service_tags)
    when status is ok/duplicate, else null with `error` set.

    This does not run the full case correlation pass -- follow with
    `cybertrace correlate --db case.db --dossier case.html` to fold every
    newly-traced wallet into the case report.
    """
    rows = _parse_batch_rows(input_file)
    if not rows:
        click.echo("[!] No addresses found in input file", err=True)
        sys.exit(1)

    results = asyncio.run(_run_wallet_batch(
        rows, db_path, max_hops=max_hops, deep=deep,
        concurrency=concurrency or config.max_concurrent))

    successful = sum(1 for r in results if r['result'] is not None)
    summary = {'total': len(results), 'successful': successful,
              'failed': len(results) - successful, 'wallets': results}

    if output_format == 'json':
        import json as _json
        click.echo(_json.dumps(summary, indent=2))
        return

    for r in results:
        line = f"{r['wallet']} [{r['chain'] or 'auto'}] -> {r['status']}"
        if r['status'] in ('ok', 'duplicate') and r['result'] and r['result']['exchange']:
            line += (f" · {r['result']['exchange']} "
                    f"({r['result']['hops']} hop(s), {r['result']['proximity']})")
        elif r['status'] in ('ok', 'duplicate') and r['result'] and \
                (r['result'].get('vasp_candidates') or {}).get('primary_candidate'):
            cand = r['result']['vasp_candidates']
            line += f" · candidate: {cand['primary_candidate']} ({cand['strength']}, fingerprint-based)"
        elif r['error']:
            line += f" · {r['error']}"
        click.echo(line)
    click.echo(f"\n{summary['total']} total · {summary['successful']} successful · "
              f"{summary['failed']} failed")


@cli.group('crypto')
def crypto_group():
    """Crypto investigation workflow commands (Loop 53) -- the canonical,
    composed result. Wraps trace-wallet/trace-cross-chain/typology/graph/
    LEA-action logic already built rather than duplicating any of it; use
    trace-wallet/trace-cross-chain directly for their own narrower output."""


@crypto_group.command('investigate')
@click.argument('address')
@click.option('--db', 'db_path', required=True, type=click.Path(exists=True, dir_okay=False),
              help='Evidence store to trace through')
@click.option('--max-hops', default=4, show_default=True,
              help='Furthest layering depth to search for a labeled exchange')
@click.option('--max-transactions', default=500, show_default=True,
              help='Bound on per-transaction rows read from the transactions table')
@click.option('--chain', default=None, type=click.Choice(_WALLET_CHAINS),
              help='Chain ADDRESS was searched on. Required to trace a bnb/polygon '
                   'wallet -- a 0x address otherwise looks up ethereum only.')
@click.option('--output', '-o', 'output_format', default='table',
              type=click.Choice(['table', 'json']), help='Output format')
def crypto_investigate_cmd(address: str, db_path: str, max_hops: int, max_transactions: int,
                           chain: Optional[str], output_format: str):
    """
    The canonical Loop 53 crypto investigation for a wallet already searched
    into this case: fund-flow path, investigation graph, VASP exposure/
    control, behavioral typology signals, cross-chain events (confirmed vs
    candidate), explainable risk, a chronological timeline, and LEA
    recommendations -- in one composed result.

    \b
      cybertrace crypto investigate bc1q... --db case.db
      cybertrace crypto investigate bc1q... --db case.db --json
    """
    from .crypto_investigation import investigate_wallet
    from .evidence import EvidenceStore

    with EvidenceStore(db_path) as store:
        result = investigate_wallet(store, address, chain=chain, max_hops=max_hops,
                                    max_transactions=max_transactions)

    if result is None:
        click.echo(f"[!] {address!r} was never searched into this case", err=True)
        sys.exit(1)

    if output_format == 'json':
        import json as _json
        click.echo(_json.dumps(result, indent=2))
        return

    click.echo(f"Wallet: {result['address']} ({result['chain']})")
    click.echo(f"Transactions: {len(result['transactions'])} recorded "
              f"({result['transaction_status']})")
    vi = result['vasp_investigation'] or {}
    if vi.get('primary_vasp'):
        click.echo(f"VASP exposure: {vi['primary_vasp']} ({vi.get('attribution_tier')}, "
                  f"control {vi.get('control_status')})")
    else:
        click.echo("VASP exposure: none found")
    click.echo(f"Graph: {result['graph_summary']['node_count']} node(s), "
              f"{result['graph_summary']['edge_count']} edge(s)")
    signals = [s for s in result['typology_signals'] if s['status'] == 'DETECTED']
    if signals:
        click.echo("Behavioral signals:")
        for s in signals:
            click.echo(f"  - {s['signal']} ({s['severity']}, confidence {s['confidence']}): "
                      f"{s['explanation']}")
    else:
        click.echo("Behavioral signals: none detected")
    if result['cross_chain_events']:
        click.echo("Cross-chain events:")
        for ev in result['cross_chain_events']:
            click.echo(f"  - {ev['event_type']}: {ev['source_chain']} -> "
                      f"{ev.get('dest_chain') or 'unknown'} via {ev['source_api']}")
    risk = result['risk']
    if risk['risk_score'] is None:
        click.echo(f"Risk: {risk['risk_level']} ({risk['risk_policy_version']})")
    else:
        click.echo(f"Risk: {risk['risk_level']} — score {risk['risk_score']} "
                  f"({risk['risk_policy_version']}), categories: "
                  f"{', '.join(risk['risk_categories'])}")
    if result['recommended_actions']:
        click.echo("LEA recommendations:")
        for a in result['recommended_actions']:
            click.echo(f"  - [{a['confidence']}] {a['action']}: {a['reason']}")
    else:
        click.echo("LEA recommendations: none")


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


@cli.command('providers')
@click.option('--json', 'as_json', is_flag=True, help='Output as JSON')
@click.option('--refresh', is_flag=True, help='Bypass the health-check cache')
def providers_cmd(as_json: bool, refresh: bool):
    """Check live-provider health: LIVE / DEGRADED / DOWN / NOT_CONFIGURED.

    "Configured" (a key exists) is not the same as "live" (the API actually
    answered) -- unlike `config --check`, this makes a real, timed request to
    each provider CyberTrace calls, cached for a few minutes so repeat checks
    don't spend quota against a rate-limited free-tier key.
    """
    import asyncio
    import json as _json

    from .provider_health import capability_summary, check_all

    entries = asyncio.run(check_all(force=refresh))
    capabilities = capability_summary(entries)
    if as_json:
        click.echo(_json.dumps({"providers": [e.to_dict() for e in entries],
                                 "capabilities": capabilities}, indent=2))
        return

    click.echo("\n=== CyberTrace Provider Health ===\n")
    icon = {'LIVE': '✓', 'DEGRADED': '~', 'DOWN': '✗', 'NOT_CONFIGURED': '-'}
    for e in entries:
        latency = f"{e.latency_ms:.0f}ms" if e.latency_ms is not None else '-'
        click.echo(f"  [{icon.get(e.status, '?')}] {e.provider:22} {e.status:15} {latency:8}  {e.capability}")
        if e.reason:
            click.echo(f"        {e.reason}")
    live = sum(1 for e in entries if e.status == 'LIVE')
    click.echo(f"\n  {live}/{len(entries)} providers live. No provider here has an "
               f"automatic fallback today -- see each row's reason when DOWN/NOT_CONFIGURED.\n")

    click.echo("=== Capability Availability ===")
    click.echo("  (a provider being DOWN does not mean the capability is -- see if another")
    click.echo("   provider covers the same chain; vasp_attribution is cross-chain, not")
    click.echo("   part of any one chain's bucket)\n")
    cap_icon = {'AVAILABLE': '✓', 'DEGRADED': '~', 'UNAVAILABLE': '✗'}
    for name, status in capabilities.items():
        click.echo(f"  [{cap_icon.get(status, '?')}] {name:20} {status}")
    click.echo()


@cli.command('detect')
@click.argument('address')
@click.option('--json', 'as_json', is_flag=True, help='Output as JSON')
def detect_cmd(address: str, as_json: bool):
    """Detect an address's format and, for an ambiguous EVM address, probe
    which networks it actually has activity on.

    Format alone never proves network identity: a 0x address is valid on
    Ethereum, BNB Chain and Polygon at once (see chain_caveat). For those,
    this runs a live check against each chain CyberTrace supports and reports
    which show real transaction history -- not just which "could" match.
    """
    import asyncio
    import json as _json

    from .detector import btc_address_family, chain_caveat, detect_input_type
    from .modules.bitcoin_module import BitcoinModule

    specific, module_type = detect_input_type(address)
    out = {'address': address, 'format': specific, 'module_type': module_type,
           'caveat': chain_caveat(specific), 'btc_family': None, 'networks': None}

    if specific in ('btc_legacy', 'btc_bech32'):
        out['btc_family'] = btc_address_family(address)
    elif specific == 'ethereum':
        async def _go():
            async with BitcoinModule() as m:
                return await m.probe_evm_networks(address)
        out['networks'] = asyncio.run(_go())

    if as_json:
        click.echo(_json.dumps(out, indent=2))
        return

    click.echo(f"\nFormat detected: {out['format']} → module: {out['module_type']}")
    if out['btc_family']:
        click.echo(f"Address family: {out['btc_family']}")
        click.echo("Bitcoin is a single network — format confirms which chain; it does "
                   "NOT confirm the address has ever been used. Run `cybertrace search` "
                   "to check real activity.")
    if out['caveat']:
        click.echo(f"[!] {out['caveat']}")
    if out['networks']:
        click.echo("\nNetwork activity probe (format ≠ proof of network):")
        for chain, info in out['networks'].items():
            if not info['checked']:
                mark, note = '?', info['error'] or 'could not check'
            elif info['active']:
                mark, note = '✓', 'activity found'
            else:
                mark, note = '-', 'no activity found'
            click.echo(f"  [{mark}] {chain:10} {note}")


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
