"""Evidence-model tests: normalization gate, provenance chain, clone guard."""

import base64
import hashlib
import json
import re
import struct
from datetime import datetime, timezone

import pytest

from cybertrace.correlate import market_artifact_map, markets_for_entity
from cybertrace.evidence import (
    EvidenceStore, ingest, detect_clones, fingerprint_signature, page_similarity,
    structural_similarity,
)
from cybertrace.modules.base import ModuleResult, SourceResult
from cybertrace.modules.email_module import EmailModule
from cybertrace.normalize import (
    dom_simhash, norm_asn, norm_btc, norm_domain, norm_email, norm_eth, norm_ip,
    norm_onion, norm_pgp, norm_username, norm_xmr, pgp_certifiers,
    pgp_signature_issuers, simhash_similarity,
)

# A real mainnet address (block 170 coinbase) and the BIP-173 P2WPKH vector.
BTC_VALID = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
BTC_BECH32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
XMR_VALID = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3"
             "XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
def onion(seed: str) -> str:
    """A synthetic but checksum-VALID v3 address, one per seed character.

    norm_onion verifies the checksum a real address carries, so `"a" * 56` is
    not a stand-in for an onion any more — it is exactly the corrupted string
    the gate exists to refuse. Fixtures have to be addresses that could exist.
    """
    pub = (seed.encode() * 32)[:32]
    chk = hashlib.sha3_256(b".onion checksum" + pub + b"\x03").digest()[:2]
    return base64.b32encode(pub + chk + b"\x03").decode().lower() + ".onion"


ONION_A = onion("a")
ONION_B = onion("b")


def _pubkey_packet(modulus: int, created: int = 1_700_000_000) -> bytes:
    """A structurally valid v4 RSA public-key packet body (RFC 4880 5.5.2)."""
    body = struct.pack(">BIB", 4, created, 1)  # version, creation time, RSA
    for mpi in (modulus, 65537):
        raw = mpi.to_bytes((mpi.bit_length() + 7) // 8, "big")
        body += struct.pack(">H", mpi.bit_length()) + raw
    return bytes([0x99]) + struct.pack(">H", len(body)) + body


def _armor(packet: bytes, width: int = 64, headers: str = "") -> str:
    b64 = base64.b64encode(packet).decode()
    wrapped = "\n".join(b64[i:i + width] for i in range(0, len(b64), width))
    return ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n" + headers + "\n"
            + wrapped + "\n=Ab3d\n-----END PGP PUBLIC KEY BLOCK-----")


KEY_A = _armor(_pubkey_packet((1 << 2047) | 0xDEADBEEF))
KEY_B = _armor(_pubkey_packet((1 << 2047) | 0xFEEDFACE))


# --- normalization gate ------------------------------------------------------

def test_btc_checksum_is_enforced():
    assert norm_btc(BTC_VALID) == f"BTC:{BTC_VALID}"
    assert norm_btc(BTC_BECH32) == f"BTC:{BTC_BECH32}"
    # One character changed: passes the module's regex, fails base58check.
    assert norm_btc("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3") is None
    assert norm_btc("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5") is None
    assert norm_btc("notanaddress") is None


def test_xmr_and_eth():
    """XMR validation is structural (no keccak checksum — see norm_xmr), so it
    rejects wrong length, wrong prefix and block overflow, but a well-formed
    base58 run still passes. Asserted here so the ceiling stays visible."""
    assert norm_xmr(XMR_VALID) == f"XMR:{XMR_VALID}"
    assert norm_xmr(XMR_VALID[:-1]) is None            # length
    assert norm_xmr("2" + XMR_VALID[1:]) is None       # decodes to unknown prefix 6
    assert norm_xmr("z" * 95) is None                  # block overflows its width
    assert norm_xmr("4" + "A" * 94) is not None        # known gap: no checksum
    assert norm_eth("0x" + "Ab" * 20) == "ETH:0x" + "ab" * 20
    assert norm_eth("0x1234") is None


def test_rejects_are_counted():
    """A refused value must leave a trace. It writes no row anywhere, so without
    the counter `extracted` is unrecoverable and precision cannot be computed."""
    store = EvidenceStore(":memory:")
    assert store.upsert_entity("EMAIL", "logo_dark_48@2x.webp") is None
    assert store.upsert_entity("EMAIL", "ops@blockchair.com") is not None
    store.upsert_entity("EMAIL", "logo_dark_48@2x.webp")          # seen twice
    assert store.rejected[("EMAIL", "logo_dark_48@2x.webp")] == 2
    assert sum(store.rejected.values()) == 2                      # accepted not counted
    store.close()


def test_misc_normalizers():
    # A real domain on purpose: reserved names are rejected outright now, so
    # using one here would test the placeholder guard instead of the casing and
    # trailing-punctuation stripping this line is actually for.
    assert norm_email("  BOSS@Morke.RU.") == "boss@morke.ru"
    assert norm_email("not-an-email") is None
    # Asset filenames are the false-positive family seen in the wild (Blockchair
    # served logo_dark_48@2x.webp, which minted an EMAIL and a USERNAME node).
    assert norm_email("logo_dark_48@2x.webp") is None
    assert norm_email("image@2x.png") is None
    assert norm_email("sprite@3x.svg") is None
    assert norm_email("op@proton.me") == "op@proton.me"
    assert norm_email("foo@bar.com") is None       # metasyntactic, i.e. documentation
    assert norm_email(f"admin@{ONION_A}") == f"admin@{ONION_A}"   # real onion mailbox
    assert norm_email("admin@example.onion") is None              # placeholder onion
    assert norm_ip(" 1.2.3.4 ") == "1.2.3.4"
    assert norm_ip("999.1.1.1") is None
    assert norm_onion("http://" + ONION_A.upper() + "/index") == ONION_A
    assert norm_onion("short.onion") is None
    assert norm_domain("https://Mail.RISEUP.net:8080/path?q=1") == "mail.riseup.net"
    assert norm_domain(ONION_A) is None                # an onion is not a domain
    # A literal address in a URL is a host — there is an entity type for that.
    # 81chan referenced http://78.17.212.207/, which became a DOMAIN whose
    # "registrable" form was 212.207, so any second address in that /16 would
    # have grouped with it as one namespace.
    assert norm_domain("78.17.212.207") is None
    assert norm_domain("http://78.17.212.207:8080/x") is None
    assert norm_username("Agent_Zero") == "Agent_Zero"
    assert norm_username("a") is None


def test_placeholder_emails_never_reach_enrichment():
    """Rejected at normalize, not at scoring, because the email pivot runs a
    keyserver lookup: an accepted `mail@example.org` returns the PGP keys of
    whoever used that address in documentation, and those unrelated people
    become operator candidates in the case."""
    for value in ("mail@example.org", "admin@esample.org", "user@example.com",
                  "sysop@domain.tld", "test@onionmail.info", "test1@onionmail.info",
                  "youremail@gmail.com", "someone@host.invalid"):
        assert norm_email(value) is None, value
    # Role mailboxes on real domains are the genuine article and must survive.
    for value in ("abuse@morke.ru", "support@dnmx.cc", "admin@mail2tor.com"):
        assert norm_email(value) == value, value


def test_mailing_list_instruction_fragments_are_not_mailboxes():
    """`listname-subscribe@lists.riseup.net` in Riseup's list instructions was
    extracted from the first character the pattern could match, yielding
    `-subscribe@lists.riseup.net` — an address belonging to nobody, minted as an
    operator artifact. The guard is on the shape, so the whole
    `-request@`/`-owner@` family goes with it, and real hyphens survive."""
    for value in ("-subscribe@lists.riseup.net", "-unsubscribe@lists.riseup.net",
                  "-request@lists.riseup.net", "list-@riseup.net",
                  "admin.@riseup.net", "a..b@riseup.net"):
        assert norm_email(value) is None, value
    for value in ("cypherpunks-subscribe@lists.riseup.net", "a.b-c@riseup.net",
                  "honeytroll@riseup.net"):
        assert norm_email(value) == value, value
    # A leading dot is prose punctuation, not part of the local-part, and the
    # strip at the top of norm_email already recovers the address it precedes.
    assert norm_email(".admin@riseup.net") == "admin@riseup.net"


def test_onion_subdomain_resolves_to_one_node():
    """Facebook and Reddit publish `www.<addr>.onion`. The circuit is built to
    the .onion address itself, so the prefix is vhost routing, not identity —
    detector.normalize_input drops it and this must agree, or the same hidden
    service becomes two entities that never correlate."""
    assert norm_onion(f"www.{ONION_A}") == ONION_A
    assert norm_onion(f"https://WWW.{ONION_A.upper()}/dir/page") == ONION_A
    assert norm_onion(f"mail.sub.{ONION_A}:8080") == ONION_A
    assert norm_onion(f"www.{ONION_A[:-6]}") is None   # still must end in .onion


def test_a_directorys_mangled_links_are_not_addresses():
    """tor.taxi prints every link with one character changed, on purpose.

    Its front page says the links are "unclickable for your safety" — an
    anti-phishing measure — so the 140 addresses it displays are 140 services
    that do not exist. Riseup's real address is published there as `…ceo3ak7…`
    for `…ceo3ah7…`, Cryptostorm's as `…gvku2c…` for `…gvcu2c…`. Both are
    well-formed and both must be refused, because a v3 address carries the
    checksum that proves it: shape is not identity.
    """
    riseup = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion"
    storm = "stormwayszuh4juycoy4kwoww5gvcu2c4tdtpkup667pdwe4qenzwayd.onion"
    assert norm_onion(riseup) == riseup and norm_onion(storm) == storm
    assert norm_onion(riseup.replace("ceo3ah7", "ceo3ak7")) is None
    assert norm_onion(storm.replace("gvcu2c", "gvku2c")) is None
    # The corruption is invisible to a shape check, which is the whole problem.
    assert re.fullmatch(r"[a-z2-7]{56}\.onion", riseup.replace("ceo3ah7", "ceo3ak7"))


def test_boilerplate_domains_are_not_infrastructure():
    """Two markets both linking github.com share page furniture, not hosting.
    Admitted as DOMAIN entities these mint INFRA candidates and then SUCCESSOR
    hypotheses, so the stoplist applies before the entity exists."""
    for value in ("github.com", "www.w3.org", "www.torproject.org", "s.w.org",
                  "wordpress.org", "drive.google.com", "cdn.jsdelivr.net"):
        assert norm_domain(value) is None, value
    for value in ("riseup.net", "mail.riseup.net", "dnmx.cc", "cock.li"):
        assert norm_domain(value) == value, value


def test_documentation_and_overlay_names_are_not_domains():
    """Two refusals norm_email already made and norm_domain did not.

    RFC 2606 names: zzzchan's FAQ prints `example.com` in an instruction, so the
    store minted it as a DOMAIN. `webmaster@example.com` was correctly no
    mailbox while the host beside it became an entity — and a documentation name
    is the one host guaranteed to turn up on unrelated sites for unrelated
    reasons, so any two of them would have shared it.

    Overlay addresses: `.onion` was already refused because an onion has its own
    entity type, and an I2P b32 or Lokinet address is the same kind of thing.
    Both were live entities on the v5+v6 corpus, each shared by two targets, and
    `_registrable` reads the last two labels of a b32 as `b32.i2p` — so every
    eepsite in a corpus would group into one namespace and draw the multi-host
    bonus meant for an operator's own subdomains.
    """
    for value in ("example.com", "www.example.org", "mail.example.net",
                  "yourdomain.com", "host.localhost", "site.test", "foo.invalid"):
        assert norm_domain(value) is None, value
    for value in ("4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq.b32.i2p",
                  "kqrtg5wz4qbyjprujkz33gza7r73iw3ainqp1mz5zmu16symcdwy.loki",
                  f"{ONION_A}", f"http://{ONION_A}/x"):
        assert norm_domain(value) is None, value
    # Real hosts that merely resemble them must survive: `.li` is a TLD,
    # `example` as a label is not the reserved name.
    for value in ("example.cock.li", "exemple.fr", "test.riseup.net"):
        assert norm_domain(value) == value, value


def test_a_mailbox_at_page_furniture_is_page_furniture():
    """The corpus's headline case, and the one commonness provably cannot fix.

    SecureDrop ships `gettor@torproject.org` in its Tor install instructions, so
    four independently-operated newsrooms — CBC, Forbes, The Guardian,
    ProPublica — published the same mailbox. EMAIL is a full-control artifact
    class, so the engine promoted it to one OPERATOR candidate spanning all four
    at score 0.47, against 0.58 for the genuine DNMX pair.

    Frequency scoring could not catch it and never could: with 5 of the world's
    SecureDrop instances in the corpus, the platform's own address measures as
    RARE (0.67, against a 0.5 floor). A corpus never holds enough of a family to
    expose that family's furniture by counting. What does catch it is already in
    the file — torproject.org is on the boilerplate stoplist — and only
    norm_domain was consulting it.
    """
    for value in ("gettor@torproject.org", "security@github.com",
                  "noreply@wordpress.org", "press@mozilla.org"):
        assert norm_email(value) is None, value
    # The operator mailboxes this must not touch, including one at a domain
    # whose SITE is in the corpus.
    for value in ("support@dnmx.cc", "abuse@morke.ru", "admin@mail2tor.com",
                  "op@riseup.net"):
        assert norm_email(value) == value, value


def test_markup_and_platform_furniture_is_not_a_shared_host():
    """Each of these was, on the v5 corpus, the ONLY thing joining two unrelated
    targets: `ogp.me` (an Open Graph namespace declared in a meta prefix, no
    more a referenced host than a DTD) paired Blockchair with Riseup, `t.me`
    paired Blockchair with the Tor Project, `duckduckgo.com` paired Riseup with
    the Tor Project, `en.bitcoin.it` paired Endchan with Riseup, and WordPress's
    pingback and stats hosts paired the two DNMX addresses for a reason that has
    nothing to do with their operator.

    Only the host survives normalization, so `t.me/someone` never carried an
    operator handle here anyway — refusing the host loses no identity.
    """
    for value in ("ogp.me", "purl.org", "en.bitcoin.it", "www.gnu.org",
                  "wp-statistics.com", "archipelago.phrasewise.com",
                  "duckduckgo.com", "t.me", "x.com", "www.paypal.com"):
        assert norm_domain(value) is None, value

    # Two things the stoplist must NOT swallow, for opposite reasons.
    for value in ("onionmail.info", "lynxchan.com"):
        # A platform's own domain IS the ecosystem signal. Refuse it and two
        # servers of one mail platform share nothing, so the engine calls them
        # unrelated by accident instead of reporting SHARED_PLATFORM and why.
        assert norm_domain(value) == value, value
    for value in ("blockchair.com", "facebook.com", "reddit.com"):
        # Each is a labeled or plausible target: on its own site that clearnet
        # name is the operator's identity, not furniture.
        assert norm_domain(value) == value, value


def test_pgp_fingerprint_survives_rearmoring():
    """The point of a real fingerprint over a hash of the armor: a clone that
    re-exports a copied key must still resolve to the same identity."""
    rearmored = _armor(_pubkey_packet((1 << 2047) | 0xDEADBEEF),
                       width=40, headers="Version: GnuPG v2\nComment: rehosted\n")
    fpr = norm_pgp(KEY_A)
    assert fpr and fpr.startswith("PGP:") and len(fpr) == len("PGP:") + 40
    assert norm_pgp(rearmored) == fpr                  # armor differs, identity does not
    assert norm_pgp(KEY_B) != fpr                      # different key, different id
    assert norm_pgp("-----BEGIN PGP PUBLIC KEY BLOCK-----\ngarbage\n----") is None


def test_key_id_never_merges_into_a_fingerprint_node(tmp_path):
    """The collector falls back to a payload hash when armor won't parse. That
    weak id must stay a separate node — silently inheriting a fingerprint's
    evidential weight is exactly how a false attribution gets made."""
    assert norm_pgp("deadbeefdeadbeef") == "PGP:KEYID:DEADBEEFDEADBEEF"
    assert norm_pgp("deadbeefdeadbeef") != norm_pgp(KEY_A)
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, pgp_keys=[{'key_id': 'deadbeefdeadbeef'},
                                          {'armored': KEY_A}]), store)
        keys = {r["normalized_value"]
                for r in store._all("SELECT normalized_value FROM entities WHERE etype='PGP_KEY'")}
        assert len(keys) == 2 and any(k.startswith("pgp:keyid:") for k in keys)


def test_unnormalizable_value_creates_no_entity(tmp_path):
    """No normalized value, no entity, no edge — the rule the model rests on."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        assert store.upsert_entity("BTC_ADDRESS", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3") is None
        assert store._all("SELECT * FROM entities WHERE etype='BTC_ADDRESS'") == []


# --- ingest + provenance -----------------------------------------------------

def _result(target, seen=datetime(2026, 1, 10, tzinfo=timezone.utc), **onion_data):
    r = ModuleResult(target=target, target_type='darkweb', module='darkweb')
    r.sources['target_onion'] = SourceResult(
        source='target_onion', success=True, timestamp=seen,
        data={'online': True, **onion_data},
    )
    return r


def test_fingerprint_only_when_it_distinguishes():
    """A shared web server is not a shared operator.

    DarkForest served `X-Powered-By: the almighty n0tr1v` — hand-written, close
    to a build signature, and the strongest tell on a login-wall page that
    yielded no other artifact. A bare `Server: nginx` is the opposite: minting a
    node for it would link every nginx market to every other one.
    """
    custom = {'X-Powered-By': 'the almighty n0tr1v', 'cookie_names': ['_csrf']}
    assert fingerprint_signature(custom)
    assert fingerprint_signature({'Server': 'nginx'}) is None
    assert fingerprint_signature({'Server': 'Apache/2.4.57'}) is None
    assert fingerprint_signature({'Server': 'nginx', 'X-Powered-By': 'PHP/8.1.2'}) is None
    assert fingerprint_signature({}) is None
    # Header order between two visits must not fork one operator into two nodes.
    assert fingerprint_signature({'Server': 'zz', 'cookie_names': ['b', 'a']}) == \
           fingerprint_signature({'cookie_names': ['a', 'b'], 'Server': 'zz'})

    # Two markets sharing a hand-written banner must land on ONE node — that is
    # the whole point of giving the signature an identity.
    store = EvidenceStore(":memory:")
    for onion in (ONION_A, ONION_B):
        ingest(_result(onion, server_fingerprint=custom), store)
    fps = store.conn.execute(
        "SELECT COUNT(*) c FROM entities WHERE etype='HTTP_FINGERPRINT'").fetchone()["c"]
    assert fps == 1
    assert store.conn.execute(
        "SELECT COUNT(*) c FROM relationships "
        "WHERE rtype='HAS_FINGERPRINT'").fetchone()["c"] == 2
    store.close()

    store = EvidenceStore(":memory:")
    ingest(_result(ONION_A, server_fingerprint={'Server': 'nginx'}), store)
    assert store.conn.execute(
        "SELECT COUNT(*) c FROM entities WHERE etype='HTTP_FINGERPRINT'").fetchone()["c"] == 0
    store.close()


def test_a_timestamp_is_not_a_build_signature():
    """Per-request and per-revision headers are collected, never identity.

    Both halves of this failed on the v5 corpus. Precision: a Last-Modified date
    is not a generic banner, so its presence made `{Server: nginx}` "distinctive"
    and minted an entity for a plain nginx — four targets carried exactly that
    shape. Stability: an identity containing the page's own modification date
    changes every time the operator edits the page, so the one signal a
    self-hosted build gives you could never match a second capture of itself.
    """
    edited = {'Server': 'nginx', 'Last-Modified': 'Fri, 14 Aug 2026 01:53:22 GMT'}
    assert fingerprint_signature(edited) is None
    assert fingerprint_signature({'Server': 'nginx', 'X-Runtime': '0.076696'}) is None
    assert fingerprint_signature({'Server': 'Apache', 'ETag': 'W/"1a2b3c"'}) is None

    # A real signature keeps its identity across a re-crawl that changed the page.
    build = {'X-Powered-By': 'the almighty n0tr1v', 'cookie_names': ['_csrf']}
    assert fingerprint_signature({**build, 'Last-Modified': 'Mon, 03 Aug 2026 00:00:00 GMT'}) \
        == fingerprint_signature({**build, 'Last-Modified': 'Tue, 04 Aug 2026 11:11:11 GMT'}) \
        == fingerprint_signature(build)


def test_index_hits_do_not_become_target_links():
    """Search-index co-occurrence must not become a LINKS_TO edge.

    Seen in the wild: mentalhub's onion was unreachable, so nothing was fetched,
    yet Torch's result list gave the market three edges to a link directory that
    merely ranked beside it. Two down markets sharing that directory then look
    like one operator. The same list from an actual visit IS a real link.
    """
    others = [onion("b"), onion("c")]

    r = ModuleResult(target=ONION_A, target_type='darkweb', module='darkweb')
    r.sources['torch'] = SourceResult(
        source='torch', success=True, timestamp=datetime(2026, 1, 10, tzinfo=timezone.utc),
        data={'onion_addresses_found': others + [ONION_A], 'emails': ['op@morke.ru']})

    store = EvidenceStore(":memory:")
    assert ingest(r, store), "the index snapshot itself must still be recorded"
    links = store.conn.execute(
        "SELECT COUNT(*) c FROM relationships WHERE rtype='LINKS_TO'").fetchone()["c"]
    assert links == 0
    # Non-onion artifacts from an index hit are still evidence about the target.
    assert store.find_entity("EMAIL", "op@morke.ru") is not None
    store.close()

    visited = _result(ONION_A, onion_addresses_found=others + [ONION_A])
    store = EvidenceStore(":memory:")
    ingest(visited, store)
    rows = store.conn.execute(
        "SELECT b.normalized_value v FROM relationships r "
        "JOIN entities b ON b.entity_id=r.target_entity_id "
        "WHERE r.rtype='LINKS_TO'").fetchall()
    assert {row["v"] for row in rows} == set(others)   # own address excluded, not self-linked
    store.close()


# --- M4 enrichment routing ---------------------------------------------------

def _ip_summary(**over):
    return {'ip': '5.5.5.5', 'org': 'DigitalOcean LLC', 'asn': 'AS14061',
            'hostname': 'vps.morke.ru', 'is_hosting': True, **over}


def _pivot_result(target, pivots, seen=datetime(2026, 1, 12, tzinfo=timezone.utc)):
    r = ModuleResult(target=target, target_type='darkweb', module='darkweb')
    r.sources['operator_pivot'] = SourceResult(
        source='operator_pivot', success=True, timestamp=seen,
        data={'pivoted': len(pivots), 'results': pivots})
    return r


def test_norm_asn_collapses_forms_and_rejects_company_digits():
    assert norm_asn('AS15169') == norm_asn('15169') == norm_asn('AS15169 Google LLC')
    # A digit inside a company name is not an AS number.
    assert norm_asn('Level 3 Parent, LLC') is None
    assert norm_asn('DigitalOcean') is None


def test_pivot_enrichment_lands_on_the_ip_entity(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_pivot_result(ONION_A, [
            {'target': '5.5.5.5', 'type': 'ip', 'summary': _ip_summary()},
        ]), store)

        ip = store.find_entity("IP", "5.5.5.5")
        meta = store.metadata(ip)
        assert meta["ip_class"] == "INFRA_IP"      # from the source's own flag
        assert meta["asn"] == "AS14061" and meta["org"] == "DigitalOcean LLC"

        # ASN and provider are shared nodes, not just attributes.
        asn = store.find_entity("ASN", "AS14061")
        assert store._one("SELECT 1 FROM relationships WHERE source_entity_id=? "
                          "AND target_entity_id=? AND rtype='BELONGS_TO_ASN'", (ip, asn))
        assert store.find_entity("DOMAIN", "vps.morke.ru")


def test_pivot_enrichment_never_mints_a_market(tmp_path):
    """An enriched IP is a host, not a storefront — a MARKET node here would put
    a phantom market into every correlation."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        r = ModuleResult(target='5.5.5.5', target_type='ip', module='ip')
        r.sources['ipinfo'] = SourceResult(source='ipinfo', success=True,
                                           timestamp=datetime(2026, 1, 12, tzinfo=timezone.utc),
                                           data={})
        r.summary = _ip_summary(is_hosting=False, is_proxy=True)
        assert ingest(r, store)

        assert store.find_entity("MARKET", "5.5.5.5") is None
        assert store.metadata(store.find_entity("IP", "5.5.5.5"))["ip_class"] == "VPN_IP"


def test_keyserver_fingerprint_links_email_to_key(tmp_path):
    fpr = "a" * 40
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_pivot_result(ONION_A, [
            {'target': 'op@proton.me', 'type': 'email',
             'summary': {'has_pgp_key': True, 'pgp_fingerprints': [fpr]}},
        ]), store)

        email = store.find_entity("EMAIL", "op@proton.me")
        key = store.find_entity("PGP_KEY", fpr)
        assert email and key
        rel = store._one("SELECT rel_id FROM relationships WHERE source_entity_id=? "
                         "AND target_entity_id=? AND rtype='ASSOCIATED_WITH'", (email, key))
        assert rel
        # Provenance survives the pivot: the edge is backed by evidence.
        assert store._one("SELECT 1 FROM evidence WHERE relationship_id=?",
                          (rel["rel_id"],))


def test_mr_index_parse_keeps_uids_drops_revoked():
    text = ("info:1:2\n"
            "pub:" + "b" * 40 + ":1:4096:1700000000::\n"
            "uid:Dark Op <op%40proton.me>:1700000000::\n"
            "pub:" + "c" * 40 + ":1:4096:1600000000::r\n"
            "uid:Old Key <old%40proton.me>:1600000000::r\n")
    parsed = EmailModule._parse_mr_index(text)
    assert parsed == [("b" * 40, ["op@proton.me"])]


def test_ingest_classifies_ip_owner(tmp_path):
    """A VPN egress must not reach the dossier looking like an origin host."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, favicon={'shodan_matches': [
            {'ip': '1.1.1.1', 'org': 'M247 Europe SRL', 'isp': 'Mullvad VPN'},
            {'ip': '2.2.2.2', 'org': 'ExampleHost BV'},
        ]}), store)

        assert store.metadata(store.find_entity("IP", "1.1.1.1")) == {
            "org": "M247 Europe SRL", "isp": "Mullvad VPN", "ip_class": "VPN_IP"}
        # Unknown stays unknown: a hosting name is not proof of an origin host.
        assert store.metadata(store.find_entity("IP", "2.2.2.2"))["ip_class"] == "UNKNOWN"


def test_a_tor_relay_host_argues_against_the_candidate_that_named_it(tmp_path):
    """The negative control, end to end.

    A favicon match on an address that Tor Metrics places a relay on is the
    weakest possible hosting evidence: the machine carries traffic for the whole
    network, so an icon or a service seen there is shared with everyone. Read
    the other way round — "the operator's host is on Tor infrastructure!" — it
    would be the most confident wrong answer the tool could give.

    Three states, and only one of them may reclassify. ExoneraTor answers
    positive, negative, or cannot answer at all, and the module reports the
    third as a failed source precisely so it cannot arrive here looking like a
    clean negative.
    """
    from cybertrace.correlate import recommended_actions
    from cybertrace.evidence import classify_ip

    relay = {'tor_relay': True, 'checked_date': '2026-08-13'}
    assert classify_ip("Some Hosting Ltd", None, relay) == "TOR_RELAY"
    # …and it outranks every other reading of the same host, which is the point:
    # a relay running on a rented VPS is still shared Tor infrastructure.
    assert classify_ip("Some Hosting Ltd", None, {**relay, 'is_hosting': True}) \
        == "TOR_RELAY"
    assert classify_ip("Some Hosting Ltd", None, {'tor_relay': False}) == "UNKNOWN"
    assert classify_ip("Some Hosting Ltd", None, {}) == "UNKNOWN"

    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, favicon={'favicon_mmh3': 999, 'shodan_matches': [
            {'ip': '171.25.193.25', 'org': 'Foreningen for digitala fri'}]}), store)
        ip = store.find_entity("IP", "171.25.193.25")
        ingest(_pivot_result(ONION_A, [
            {'target': '171.25.193.25', 'type': 'ip',
             'summary': {'org': 'Foreningen for digitala fri', **relay}},
        ]), store)

        assert store.metadata(ip)["ip_class"] == "TOR_RELAY"
        # The reader is told to stop, in the first line, not in a footnote.
        actions = recommended_actions("IP", "IP", "171.25.193.25", [ONION_A], "TOR_RELAY")
        assert "AGAINST" in actions[0]


def test_ingest_builds_provenance_chain(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, title='Shop', emails=['darkoperator@proton.me'],
                       bitcoin_addresses=[BTC_VALID, 'garbage-address'],
                       artifact_evidence={BTC_VALID: {'section': 'contact',
                                                      'context': 'Pay to ' + BTC_VALID}},
                       misconfigurations=[{'path': '/.env', 'leaked_ips': ['8.8.8.8']}],
                       favicon={'shodan_matches': [{'ip': '1.1.1.1', 'org': 'ExampleHost'}]}),
               store)

        types = {r["etype"] for r in store._all("SELECT etype FROM entities")}
        assert {'MARKET', 'ONION_ADDRESS', 'EMAIL', 'BTC_ADDRESS', 'IP',
                'HOSTING_PROVIDER'} <= types
        # The invalid address was dropped rather than becoming a shared node.
        assert len(store._all("SELECT 1 FROM entities WHERE etype='BTC_ADDRESS'")) == 1

        btc = store.find_entity("BTC_ADDRESS", BTC_VALID)
        market = store.find_entity("MARKET", ONION_A)
        rel = store._one("SELECT rel_id FROM relationships WHERE source_entity_id=? "
                         "AND target_entity_id=?", (market, btc))
        chain = store.provenance(rel["rel_id"])
        assert chain and chain[0]["sha256"] and chain[0]["url"] == ONION_A
        # Page section and snippet come from the collector's artifact_evidence.
        assert chain[0]["extraction_method"] == "target_onion:contact"
        assert chain[0]["section"] == "contact"
        assert "Pay to" in chain[0]["context"]


def test_reingest_is_idempotent(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        r = _result(ONION_A, emails=['op@proton.me'])
        ingest(r, store)
        before = len(store._all("SELECT 1 FROM entities"))
        ingest(r, store)
        assert len(store._all("SELECT 1 FROM entities")) == before
        assert len(store._all("SELECT 1 FROM relationships")) == \
               len(store._all("SELECT DISTINCT source_entity_id, target_entity_id, rtype "
                              "FROM relationships"))
        # A repeat capture is still a new snapshot, chained to the previous one.
        snaps = store._all("SELECT previous_snapshot_id FROM snapshots")
        assert len(snaps) == 2 and snaps[1]["previous_snapshot_id"] is not None


def test_failed_source_is_not_ingested(tmp_path):
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        r = ModuleResult(target=ONION_A, target_type='darkweb', module='darkweb')
        r.sources['target_onion'] = SourceResult(source='target_onion', success=False,
                                                 error='timeout')
        ingest(r, store)
        assert store._all("SELECT 1 FROM snapshots") == []


# --- clone guard -------------------------------------------------------------

def test_clone_suspect_blocks_naive_key_merge(tmp_path):
    """Two markets, one key, near-identical pages: the later one copied it.

    Without this the tool would report 'same PGP -> same operator' and attribute
    a clone's activity to its victim.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        shared = dict(title='DarkShop', emails=['op@proton.me'],
                      bitcoin_addresses=[BTC_VALID], pgp_keys=[{'armored': KEY_A}])
        ingest(_result(ONION_A, seen=datetime(2026, 1, 10, tzinfo=timezone.utc), **shared), store)
        ingest(_result(ONION_B, seen=datetime(2026, 8, 2, tzinfo=timezone.utc), **shared), store)

        found = detect_clones(store)
        assert len(found) == 1
        f = found[0]
        assert f["ftype"] == "CLONE_SUSPECT"
        assert f["earlier"] == ONION_A and f["later"] == ONION_B
        assert f["confidence"] >= 0.85
        assert store.findings("CLONE_SUSPECT")


def test_successor_candidate_when_pages_differ(tmp_path):
    """Same key, dissimilar sites: reads as the operator rebuilding, not a clone."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, seen=datetime(2026, 1, 10, tzinfo=timezone.utc), title='OldShop',
                       emails=['op@proton.me'], bitcoin_addresses=[BTC_VALID],
                       pgp_keys=[{'armored': KEY_A}]), store)
        ingest(_result(ONION_B, seen=datetime(2026, 8, 2, tzinfo=timezone.utc), title='NewPlace',
                       emails=['sales@example.org'], analytics_ids=['UA-1234-1'],
                       pgp_keys=[{'armored': KEY_A}]), store)

        found = detect_clones(store)
        assert [f["ftype"] for f in found] == ["SUCCESSOR_CANDIDATE"]


def test_simultaneous_sighting_yields_no_precedence_claim(tmp_path):
    """Same timestamp on both markets: nobody can be shown to have copied whom,
    so the guard must stay silent rather than guess a direction."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for onion in (ONION_A, ONION_B):
            ingest(_result(onion, seen=datetime(2026, 1, 10, tzinfo=timezone.utc), title='Shop',
                           pgp_keys=[{'armored': KEY_A}]), store)
        assert detect_clones(store) == []


def test_page_similarity_bounds():
    a = {'title': 'Shop', 'emails': ['x@y.com'], 'bitcoin_addresses': [BTC_VALID]}
    assert page_similarity(a, a) == 1.0
    assert page_similarity(a, {'title': 'Other', 'emails': ['q@z.com']}) < 0.3
    assert page_similarity({}, {}) == 0.0


# --- structural fingerprints -------------------------------------------------

SHOP_HTML = ("<html><body><div class='wrap nav'><ul><li>a</li><li>b</li></ul>"
             "<p>Buy things here</p><table><tr><td>x</td></tr></table></div></body></html>")
REWORDED = SHOP_HTML.replace("Buy things here", "Completely different wording")
OTHER_HTML = "<html><section><h1>Hi</h1><article><span>y</span></article></section></html>"


def test_dom_simhash_tracks_structure_not_wording():
    """The signal a clone cannot rewrite away. A copycat changes the prose; the
    template survives, and that is what this has to see."""
    assert dom_simhash(SHOP_HTML) == dom_simhash(REWORDED)
    assert simhash_similarity(dom_simhash(SHOP_HTML), dom_simhash(OTHER_HTML)) < 0.8
    assert dom_simhash("") is None
    assert simhash_similarity(None, "abc") == 0.0      # missing side never scores


def test_structural_similarity_prefers_pages_but_degrades(tmp_path):
    """Captures older than per-page fingerprints must fall back to the artifact
    bag, not read a missing field as 'these sites look nothing alike'."""
    with_pages = {'title': 'Shop', 'pages': [{'dom_simhash': dom_simhash(SHOP_HTML)}]}
    same = {'title': 'Shop', 'pages': [{'dom_simhash': dom_simhash(REWORDED)}]}
    assert structural_similarity(with_pages, same) == 1.0
    assert structural_similarity(with_pages, {'title': 'Shop'}) is None
    assert page_similarity(with_pages, {'title': 'Shop'}) > 0     # fallback path
    # Structure dominates once both sides have it: same artifacts, different build.
    unlike = {'title': 'Shop', 'pages': [{'dom_simhash': dom_simhash(OTHER_HTML)}]}
    assert page_similarity(with_pages, unlike) < page_similarity(with_pages, same)


# --- PGP roles and certifications --------------------------------------------

def test_signing_role_becomes_a_different_edge(tmp_path):
    """Displaying a key is what a clone does; signing with it needs the secret
    half. The two must not land on the same relationship type."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, pgp_keys=[{'armored': KEY_A, 'role': 'signing'}]), store)
        ingest(_result(ONION_B, pgp_keys=[{'armored': KEY_A, 'role': 'displayed'}]), store)

        types = {r["rtype"] for r in store._all(
            "SELECT rtype FROM relationships WHERE rtype IN ('USES_PGP','SIGNS_WITH')")}
        assert types == {"USES_PGP", "SIGNS_WITH"}
        key = store.find_entity("PGP_KEY", KEY_A)
        assert store.metadata(key)["role"] in ("signing", "displayed")


def test_certifiers_become_signed_by_edges(tmp_path):
    """A third-party certification inside a published key block is the strongest
    successor signal the graph has, and it must point signer -> signed."""
    signer = "AA" * 20
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, pgp_keys=[{'armored': KEY_A, 'certifiers': [signer]}]),
               store)
        row = store._one(
            "SELECT s.normalized_value AS src, t.normalized_value AS dst "
            "FROM relationships r JOIN entities s ON s.entity_id = r.source_entity_id "
            "JOIN entities t ON t.entity_id = r.target_entity_id WHERE r.rtype='SIGNED_BY'")
        assert row["src"] == f"pgp:{signer.lower()}"
        assert row["dst"] == norm_pgp(KEY_A).lower()


def test_real_key_block_yields_its_certifiers():
    """Parsed from packets, not from armor text: exercises subpacket walking on
    a block built here, so it cannot pass by matching a hex string in the ASCII."""
    from tests.test_evidence import _armor
    sig = _signature_packet(sig_type=0x13, issuer=bytes.fromhex("1122334455667788"))
    block = _armor(_pubkey_packet((1 << 2047) | 0xABCDEF) + sig)
    assert pgp_certifiers(block) == ["1122334455667788"]
    # A self-signature is not a certification by anyone else.
    own = norm_pgp(_armor(_pubkey_packet((1 << 2047) | 0xABCDEF))).removeprefix("PGP:")
    self_sig = _signature_packet(sig_type=0x13, issuer=bytes.fromhex(own[-16:]))
    assert pgp_certifiers(_armor(_pubkey_packet((1 << 2047) | 0xABCDEF) + self_sig)) == []


def _signature_packet(sig_type: int, issuer: bytes) -> bytes:
    """v4 signature packet carrying an issuer key-id subpacket (RFC 4880 5.2.3)."""
    subpacket = bytes([len(issuer) + 1, 16]) + issuer          # len, type 16, key id
    body = (struct.pack(">BBBB", 4, sig_type, 1, 8)            # version, type, RSA, SHA-256
            + struct.pack(">H", 0)                             # no hashed subpackets
            + struct.pack(">H", len(subpacket)) + subpacket
            + b"\x00\x00" + b"\x00\x10" + b"\x00" * 2)         # hash prefix + tiny MPI
    return bytes([0x88]) + bytes([len(body)]) + body           # old-format tag 2


# --- page lineage and discovery provenance -----------------------------------

def test_pages_get_their_own_snapshots(tmp_path):
    """An observation must resolve to the hash of the page it was read off, not
    to the whole visit — that is the difference between 'the site changed' and
    'this key left /contact'."""
    pages = [{'path': '/', 'sha256': 'a' * 64, 'dom_simhash': '1' * 16},
             {'path': '/contact', 'sha256': 'b' * 64, 'dom_simhash': '2' * 16}]
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(_result(ONION_A, pages=pages, emails=['op@proton.me'],
                       artifact_evidence={'op@proton.me': {'section': 'contact',
                                                           'page': '/contact'}}), store)
        target = store._one("SELECT target_id FROM targets WHERE url=?",
                            (ONION_A,))["target_id"]
        collectors = {r["collector"] for r in store.page_snapshots(target)}
        assert collectors == {'target_onion:page:/', 'target_onion:page:/contact'}
        # The email was published on /contact, so its observation hangs there.
        row = store._one(
            "SELECT s.collector FROM observations o JOIN snapshots s "
            "ON s.snapshot_id = o.snapshot_id JOIN entities e ON e.entity_id = o.entity_id "
            "WHERE e.normalized_value='op@proton.me'")
        assert row["collector"] == 'target_onion:page:/contact'
        # Site-level queries must not pick a page record up by accident.
        assert ':page:' not in store.latest_snapshot(target)["collector"]


def test_index_hits_are_discovery_not_links(tmp_path):
    """An index co-ranking two onions says they ranked together, nothing more.
    Recorded as DISCOVERED_VIA so it can never be read as the site linking out."""
    result = ModuleResult(target=ONION_A, target_type='darkweb', module='darkweb')
    result.sources['torch'] = SourceResult(
        source='torch', success=True, data={'onion_addresses_found': [ONION_B]})
    result.sources['target_onion'] = SourceResult(
        source='target_onion', success=True,
        data={'online': True, 'onion_addresses_found': [ONION_B]})
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(result, store)
        types = {r["rtype"] for r in store._all(
            "SELECT rtype FROM relationships WHERE rtype IN ('LINKS_TO','DISCOVERED_VIA')")}
        assert types == {"LINKS_TO", "DISCOVERED_VIA"}


def test_a_target_never_fetched_observes_nothing(tmp_path):
    """The site did not answer; an index still did. What the index had on file
    is evidence about the index, and attributing it to the target is how five
    dark onions in the v4 corpus each ended up holding between two and eleven
    artifacts nobody had ever seen on them.

    The snapshot is still written — we asked, and that is provenance — but it
    is DISCOVERY, so every read that means "observed on this target" skips it.
    """
    result = ModuleResult(target=ONION_A, target_type='darkweb', module='darkweb')
    result.sources['target_onion'] = SourceResult(
        source='target_onion', success=False,
        error='Onion unreachable via Tor (127.0.0.1:9050 is up) — the site is down')
    result.sources['torch'] = SourceResult(
        source='torch', success=True,
        data={'onion_addresses_found': [ONION_B], 'emails': ['op@morke.ru']})

    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(result, store)
        statuses = {r["collector"]: r["status"] for r in store._all(
            "SELECT collector, status FROM snapshots")}
        assert statuses == {'target_onion': 'DOWN', 'torch': 'DISCOVERY'}

        # Nothing was observed ON this target, so it holds no artifacts and
        # cannot pair with anything.
        assert market_artifact_map(store) == {}
        email = store.find_entity("EMAIL", "op@morke.ru")
        assert email is not None, "the lead itself is still recorded"
        assert markets_for_entity(store, email) == []
        # …and the edge says the site mentions it, not that the site uses it:
        # nobody reached the site to see it use anything.
        assert {r["rtype"] for r in store._all(
            "SELECT rtype FROM relationships WHERE target_entity_id=?",
            (email,))} == {"MENTIONS"}


def test_roster_addresses_do_not_become_operator_identity(tmp_path):
    """A list subscriber's address is real and is not the operator's. It stays
    in the graph as a MENTIONS lead; the contact mailbox beside it keeps the
    USES_EMAIL edge that makes it an attribution artifact."""
    result = _result(
        ONION_A,
        emails=['honeytroll@riseup.net', 'support@dnmx.cc'],
        artifact_evidence={'honeytroll@riseup.net': {'section': 'roster'},
                           'support@dnmx.cc': {'section': 'contact'}})
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(result, store)
        edges = {r["v"]: r["rtype"] for r in store._all(
            "SELECT e.normalized_value v, r.rtype FROM relationships r "
            "JOIN entities e ON e.entity_id = r.target_entity_id "
            "WHERE e.etype='EMAIL'")}
        assert edges == {'honeytroll@riseup.net': 'MENTIONS',
                         'support@dnmx.cc': 'USES_EMAIL'}


def test_a_quoted_key_is_not_the_sites_key(tmp_path):
    """The strongest artifact class must go through the same gate as the rest.

    A pasted key block in a forum reply or a list archive is ordinary content,
    and the collector already sections it `quoted` — but ingest read only the
    key's ROLE, so the one artifact that carries the heaviest weight anywhere in
    the engine (f2_pgp_reuse 1.3, shared_pgp_key 1.3) was the single class that
    skipped the check. Two sites quoting one well-known key would have converged
    on its owner as their shared operator.
    """
    result = _result(ONION_A, pgp_keys=[
        {'key_id': norm_pgp(KEY_A), 'fingerprint': norm_pgp(KEY_A).removeprefix('PGP:'),
         'role': 'signing', 'section': 'quoted'},
        {'key_id': norm_pgp(KEY_B), 'fingerprint': norm_pgp(KEY_B).removeprefix('PGP:'),
         'role': 'contact', 'section': 'contact'},
    ])
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ingest(result, store)
        edges = {r["v"]: r["rtype"] for r in store._all(
            "SELECT e.normalized_value v, r.rtype FROM relationships r "
            "JOIN entities e ON e.entity_id = r.target_entity_id WHERE e.etype='PGP_KEY'")}
        assert edges == {norm_pgp(KEY_A).lower(): 'MENTIONS',
                         norm_pgp(KEY_B).lower(): 'USES_PGP'}
        # A quoted signature proves the quoted author held the secret half —
        # 'signing' must not buy the site back its attribution.
        assert 'SIGNS_WITH' not in edges.values()


def test_change_detection_ignores_per_visit_noise(tmp_path):
    """Clock skew differs on every fetch. Reporting that as a change would mark
    every target CHANGED on every re-check and bury the one that really moved —
    while the stored hash still covers the full payload, skew included."""
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        target = store.upsert_target(ONION_A)
        first = store.insert_snapshot(target, {'title': 'Shop', 'clock_skew_seconds': -810.9},
                                      collector='watch')
        same = store.insert_snapshot(target, {'title': 'Shop', 'clock_skew_seconds': 12.4},
                                     collector='watch')
        moved = store.insert_snapshot(target, {'title': 'Shop v2', 'clock_skew_seconds': 12.4},
                                      collector='watch')

        def changed(sid):
            row = store._one("SELECT diff_summary FROM snapshots WHERE snapshot_id=?", (sid,))
            return json.loads(row["diff_summary"])["changed"]

        assert changed(same) is False and changed(moved) is True
        # Provenance is not selective: the skew is still inside the hashed payload.
        hashes = {store._one("SELECT sha256 FROM snapshots WHERE snapshot_id=?",
                             (s,))["sha256"] for s in (first, same)}
        assert len(hashes) == 2


def test_one_hidden_service_cannot_be_two_targets(tmp_path):
    """A vhost label, a port and a path are routing inside ONE hidden service.

    Left un-canonicalized they fork the target row, and every cross-market floor
    in the system counts DISTINCT target_id — so a single site clears
    `min_markets=2`, the floor whose entire job is to stop one observation
    becoming an attribution. runs/raw/facebook.json and reddit.json really were
    saved under `www.<addr>.onion`, so this is a corpus that exists, not a
    hypothetical.
    """
    with EvidenceStore(str(tmp_path / "e.db")) as store:
        ids = {store.upsert_target(u) for u in (
            ONION_A, f"http://{ONION_A}", f"https://www.{ONION_A}/",
            f"http://{ONION_A}:8080/contact", f"mail.{ONION_A}")}
        assert len(ids) == 1, "one hidden service, one target row"
        assert store._one("SELECT url FROM targets")["url"] == ONION_A


def test_one_capture_ingested_twice_makes_no_operator(tmp_path):
    """The end-to-end version of the above, at the layer that would publish it.

    Measured before the fix: one dnmx capture ingested under both the bare and
    the www form produced an OPERATOR candidate (support@dnmx.cc, score 0.70)
    and a LINKED_TO edge at 0.91 — a site linked to itself, with an operator
    attributed from a single observation.
    """
    from cybertrace.correlate import candidate_operators, detect_successors

    with EvidenceStore(str(tmp_path / "e.db")) as store:
        for target in (ONION_A, f"www.{ONION_A}"):
            ingest(_result(target, emails=['support@dnmx.cc'],
                           artifact_evidence={'support@dnmx.cc': {'section': 'contact'}}),
                   store)
        assert candidate_operators(store) == []
        assert detect_successors(store) == []


def test_a_dark_site_is_evidence_but_a_dead_proxy_is_not(tmp_path):
    """'Tor is not running' is a fact about us. Recording it as the site being
    down would let a local misconfiguration manufacture a takedown."""
    for error, expected in (
            ('Onion unreachable via Tor (127.0.0.1:9050 is up) — the site is down', 1),
            ('Tor is NOT running — nothing listening on 127.0.0.1:9050', 0)):
        with EvidenceStore(":memory:") as store:
            result = ModuleResult(target=ONION_A, target_type='darkweb', module='darkweb')
            result.sources['target_onion'] = SourceResult(
                source='target_onion', success=False, error=error)
            ingest(result, store)
            assert len(store.down_windows()) == expected
            active = store._one("SELECT active FROM targets WHERE url=?",
                                (ONION_A,))["active"]
            assert active == (0 if expected else 1)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
