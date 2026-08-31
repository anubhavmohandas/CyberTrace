"""`cybertrace search` must tell a multi-shape module (breach, social) what the
target STRING actually looks like, not just which module was asked to run it.

Before this fix, `_run_search` never forwarded a `target_type` at all, so
`options.get('target_type', <default>)` inside breach_module.py/social_module.py
always hit its hardcoded default -- an email target run via `--type breach`
was silently treated as if the target_type key were absent, and a domain or
username target got the same wrong default. See cli.py's `search` command and
darkweb_module.py's target_type comment.

cli.py only re-detects the shape when the `--type` override is not already one
of the module's own `supported_types` — geoint's `--type address`/`coordinates`
already are, and free-text addresses match no detector pattern at all, so
unconditionally re-detecting would replace a valid override with the
detector's 'username' fallback and break geoint outright.
"""


import cybertrace.cli as cli_mod
from click.testing import CliRunner

from cybertrace.cli import cli
from cybertrace.modules.base import ModuleResult


def _capture_run_search(monkeypatch):
    calls = []

    async def fake_run_search(module, target, **options):
        calls.append(options.get('target_type'))
        return ModuleResult(target=target, target_type=options.get('target_type', ''),
                            module=module.name)

    monkeypatch.setattr(cli_mod, '_run_search', fake_run_search)
    return calls


def test_explicit_module_override_still_detects_the_real_target_type(monkeypatch):
    calls = _capture_run_search(monkeypatch)
    result = CliRunner().invoke(
        cli, ['search', 'user@example.com', '--type', 'breach', '-q'])
    assert result.exit_code == 0, result.output
    assert calls == ['email']


def test_explicit_module_override_on_a_username_is_not_forced_to_email(monkeypatch):
    calls = _capture_run_search(monkeypatch)
    result = CliRunner().invoke(
        cli, ['search', 'hackerman123', '--type', 'breach', '-q'])
    assert result.exit_code == 0, result.output
    assert calls == ['username']


def test_auto_detection_still_passes_the_detected_type(monkeypatch):
    calls = _capture_run_search(monkeypatch)
    result = CliRunner().invoke(cli, ['search', 'user@example.com', '-q'])
    assert result.exit_code == 0, result.output
    assert calls == ['email']


def test_explicit_module_override_on_a_phone_shape_the_detector_splits(monkeypatch):
    """detect_input_type's fine-grained label for an Indian number is
    'phone_indian', not 'phone' -- breach's supported_types only has 'phone',
    so the override must use the collapsed category, not the raw label."""
    calls = _capture_run_search(monkeypatch)
    result = CliRunner().invoke(
        cli, ['search', '+919876543210', '--type', 'breach', '-q'])
    assert result.exit_code == 0, result.output
    assert calls == ['phone']


def test_geoint_address_override_is_not_clobbered_by_redetection(monkeypatch):
    """geoint's --type address/coordinates already ARE its own supported
    shapes, so they must pass through unchanged. Free-text addresses match no
    detector pattern at all -- re-detecting them would fall through to
    detect_input_type's 'username' default and break geoint entirely, since
    'username' matches none of its target_type branches."""
    calls = _capture_run_search(monkeypatch)
    result = CliRunner().invoke(
        cli, ['search', '1600 Pennsylvania Ave, Washington DC',
              '--type', 'address', '-q'])
    assert result.exit_code == 0, result.output
    assert calls == ['address']


def test_geoint_coordinates_override_passes_through(monkeypatch):
    calls = _capture_run_search(monkeypatch)
    result = CliRunner().invoke(
        cli, ['search', '12.34,-56.78', '--type', 'coordinates', '-q'])
    assert result.exit_code == 0, result.output
    assert calls == ['coordinates']
