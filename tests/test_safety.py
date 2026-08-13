"""Content-safety gate. The false-negative cases are the point of the module;
the false-positive cases are the point of it being narrow."""

import pytest

from cybertrace.safety import BlockedContent, is_blocked_query, is_blocked_url, scrub


@pytest.mark.parametrize("query", [
    "child porn onion",
    "CSAM market",
    "pedophile forum",
    "hurtcore",
    "beheading video site",
    "daisy's destruction",
    "child\nporn",                      # split by scraped markup
])
def test_prohibited_queries_refused(query):
    assert is_blocked_query(query) is True


@pytest.mark.parametrize("query", [
    "user@example.com",
    "torpedo-market",                   # substring "pedo"
    "childhood-nostalgia-forum",        # substring "child"
    "scoregore",                        # substring "gore"
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "hackerman123",
    "",
])
def test_legitimate_targets_pass(query):
    assert is_blocked_query(query) is False


def test_url_gate():
    assert is_blocked_url("http://somehost.com/loli/index.html") is True
    assert is_blocked_url("http://bestgore.example/page") is True
    assert is_blocked_url("http://market.example/vendors") is False


def test_onion_label_never_trips_the_url_gate():
    """56 random base32 chars will eventually contain 'loli' or 'pedo'. The
    label is stripped before matching, so a market is never refused by luck."""
    for term in ("loli", "pedo", "csam"):
        label = (term + "a" * 56)[:56]
        assert is_blocked_url(f"http://{label}.onion/") is False


def test_scrub_drops_the_whole_body_or_nothing():
    assert scrub("<p>vendor pgp key here</p>") == "<p>vendor pgp key here</p>"
    assert scrub("<p>child porn</p><p>btc addr</p>") == ""
    assert scrub("") == ""


@pytest.mark.asyncio
async def test_session_gate_blocks_before_the_request_is_sent():
    """The URL gate lives in _session_for, which every fetch helper awaits."""
    from cybertrace.modules.darkweb_module import DarkwebModule

    module = DarkwebModule()
    with pytest.raises(BlockedContent):
        await module._session_for("http://example.com/jailbait/")

    # and the helpers turn that into the same no-data result as an unreachable host
    assert await module.fetch("http://example.com/jailbait/") is None
    assert await module._fetch_full("http://example.com/jailbait/") == (None, {}, "")
