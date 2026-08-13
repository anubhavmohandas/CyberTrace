"""Evidence-model tests: normalization gate, provenance chain, clone guard."""

import base64
import struct
from datetime import datetime, timezone

import pytest

from cybertrace.evidence import EvidenceStore, ingest, detect_clones, page_similarity
from cybertrace.modules.base import ModuleResult, SourceResult
from cybertrace.modules.email_module import EmailModule
from cybertrace.normalize import (
    norm_asn, norm_btc, norm_domain, norm_email, norm_eth, norm_ip, norm_onion,
    norm_pgp, norm_username, norm_xmr,
)

# A real mainnet address (block 170 coinbase) and the BIP-173 P2WPKH vector.
BTC_VALID = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
BTC_BECH32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
XMR_VALID = ("44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3"
             "XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A")
ONION_A = "a" * 56 + ".onion"
ONION_B = "b" * 56 + ".onion"


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


def test_misc_normalizers():
    assert norm_email("  BOSS@Example.COM.") == "boss@example.com"
    assert norm_email("not-an-email") is None
    assert norm_ip(" 1.2.3.4 ") == "1.2.3.4"
    assert norm_ip("999.1.1.1") is None
    assert norm_onion("http://" + ONION_A.upper() + "/index") == ONION_A
    assert norm_onion("short.onion") is None
    assert norm_domain("https://Example.COM:8080/path?q=1") == "example.com"
    assert norm_domain(ONION_A) is None                # an onion is not a domain
    assert norm_username("Agent_Zero") == "Agent_Zero"
    assert norm_username("a") is None


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


# --- M4 enrichment routing ---------------------------------------------------

def _ip_summary(**over):
    return {'ip': '5.5.5.5', 'org': 'DigitalOcean LLC', 'asn': 'AS14061',
            'hostname': 'vps.example.com', 'is_hosting': True, **over}


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
        assert store.find_entity("DOMAIN", "vps.example.com")


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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
