"""Banner must decorate the terminal without ever corrupting captured output."""

import io
import sys

from cybertrace.cli import show_banner


def _run(argv, isatty, monkeypatch):
    """Call show_banner with a faked argv/tty, returning (stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    out.isatty = lambda: isatty
    err.isatty = lambda: isatty
    monkeypatch.setattr(sys, 'argv', argv)
    monkeypatch.setattr(sys, 'stdout', out)
    monkeypatch.setattr(sys, 'stderr', err)
    show_banner()
    return out.getvalue(), err.getvalue()


def test_banner_text_goes_to_stderr_only(monkeypatch):
    # stdout carries JSON/table results, so no banner text may land there.
    # The bare screen-clear escape is the one thing stdout legitimately gets —
    # that is what clearing the terminal *is*.
    out, err = _run(['cybertrace', 'search', 'x'], True, monkeypatch)
    assert out.strip('\033[2J1;H') == ''
    assert 'ANUBHAV' in err
    assert 'CYBERTRACE' not in out


def test_silent_when_stdout_redirected(monkeypatch):
    out, err = _run(['cybertrace', 'search', 'x'], False, monkeypatch)
    assert out == ''
    assert err == ''


def test_quiet_flag_suppresses(monkeypatch):
    for flag in ('-q', '--quiet'):
        out, err = _run(['cybertrace', 'search', 'x', flag], True, monkeypatch)
        assert out == ''
        assert err == ''
