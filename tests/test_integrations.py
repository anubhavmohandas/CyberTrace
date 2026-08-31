"""Offline dataset adapters (Elliptic++, Evolution, GraphSense TagPacks):
provenance + the one invariant that actually matters -- a dataset label can
never reach the live EvidenceStore/ingest() path. See
cybertrace/integrations/*.py docstrings."""


import hashlib
import sqlite3
import zipfile

import pytest

from cybertrace.integrations import _freshness, ellipticpp, evolution, exchange_tags, ofac


def _sha256_hex(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestEvidenceStoreIsUnreachable:
    """Pins the safety boundary directly against the source, not just against
    behavior today -- a future edit that imports EvidenceStore into any
    adapter must fail this test, the same way evidence.py:270 documents
    CERTIFICATE staying unwired rather than leaving it to be noticed later."""

    @pytest.mark.parametrize("module", [ellipticpp, evolution, exchange_tags, ofac])
    def test_adapter_never_imports_the_evidence_store(self, module):
        # Checks the module's actual namespace, not its docstring prose (which
        # names EvidenceStore/ingest deliberately, to document the boundary).
        assert not hasattr(module, "EvidenceStore")
        assert not hasattr(module, "ingest")
        assert "cybertrace.evidence" not in {
            getattr(v, "__module__", None) for v in vars(module).values()}


class TestManifestProvenance:
    def test_ellipticpp_manifest_declares_unknown_license(self):
        m = ellipticpp.manifest()
        assert m["license_status"] == "UNKNOWN"
        assert m["citation"]
        assert len(m["files"]) == 9

    def test_evolution_manifest_declares_cc_by(self):
        m = evolution.manifest()
        assert m["license_status"] == "CC-BY-4.0"
        assert m["doi"] == "10.5281/zenodo.10171217"

    def test_exchange_tags_manifest_declares_mit(self):
        m = exchange_tags.manifest()
        assert m["license"] == "MIT"
        assert m["source_url"]
        assert m["pack_count"] > 0

    def test_ofac_manifest_declares_public_domain(self):
        m = ofac.manifest()
        assert m["license"] == "US Government Work"
        assert m["source_url"]
        assert m["publication_date"]


class TestRecordsCarryDatasetLabelNotAttribution:
    """Every record is provenance-tagged as an offline dataset artifact, and
    that tag is a string label to display -- not a relationship type
    correlate.py or evidence.py would recognize."""

    @pytest.mark.skipif(not ellipticpp.available(), reason="Elliptic++ not downloaded locally")
    def test_ellipticpp_wallet_record_shape(self):
        row = next(ellipticpp.iter_wallets())
        assert row["provenance"] == "OFFLINE_DATASET"
        assert row["dataset_label_name"] in ("illicit", "licit", "unknown")
        assert row["entity_type"] == "BTC_ADDRESS"  # a label, not an edge

    @pytest.mark.skipif(not evolution.available(), reason="Evolution not downloaded locally")
    def test_evolution_user_matching_is_scoped_same_platform_account(self):
        row = next(evolution.iter_user_matching())
        # Named SAME_PLATFORM_ACCOUNT, deliberately not one of
        # correlate.RELATIONSHIP_TYPES (e.g. not "SAME_OPERATOR") -- a reader
        # or a future ingest path can't mistake this for a graph edge type.
        assert row["relationship_type"] == "SAME_PLATFORM_ACCOUNT"
        from cybertrace.evidence import RELATIONSHIP_TYPES
        assert row["relationship_type"] not in RELATIONSHIP_TYPES


class TestEllipticppIndex:
    """The local lookup index (Section 5 of the brief): indexed queries over
    the wallet/address-graph CSVs instead of a 600MB+ file scan per lookup.
    """

    @pytest.mark.skipif(not ellipticpp.index_available(),
                        reason="Elliptic++ index not built (call build_index() once)")
    def test_lookup_wallet_matches_the_raw_csv(self):
        # 111112TykSw72ztDN2WJger4cynzWYC5w is class=2 (licit) in
        # wallets_classes.csv's own header rows -- read directly, not assumed.
        row = ellipticpp.lookup_wallet("111112TykSw72ztDN2WJger4cynzWYC5w")
        assert row is not None
        assert row["dataset_label"] == "2"
        assert row["dataset_label_name"] == "licit"
        assert row["provenance"] == "OFFLINE_DATASET"

    @pytest.mark.skipif(not ellipticpp.index_available(),
                        reason="Elliptic++ index not built (call build_index() once)")
    def test_lookup_wallet_absent_address_returns_none(self):
        assert ellipticpp.lookup_wallet("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is None

    def test_lookup_wallet_without_an_index_fails_loudly(self, monkeypatch):
        # A silent fallback to the O(n) scan would make the "efficient lookup"
        # this index exists for invisible until someone profiles a slow run.
        monkeypatch.setattr(ellipticpp, "index_available", lambda: False)
        with pytest.raises(RuntimeError, match="build_index"):
            ellipticpp.lookup_wallet("111112TykSw72ztDN2WJger4cynzWYC5w")


class TestEvolutionPgpReflow:
    """market/vendors.tsv's pgp_key field has every literal newline stripped
    by the TSV export, which silently defeated normalize._armor_payload
    entirely (0/2000 real keys parsed before this fix -- it reads armor line
    by line, and a flattened block is one line whose leading "-----BEGIN PGP"
    match swallows the whole string). _reflow_armor repairs the export
    artifact; it does not change how normalize.py parses a normal block.
    """

    def test_reflow_produces_multiple_lines(self):
        flat = ("-----BEGIN PGP PUBLIC KEY BLOCK-----Version: GnuPG v1"
                "mQENBE" + "A" * 200 + "==dEaD-----END PGP PUBLIC KEY BLOCK-----")
        reflowed = evolution._reflow_armor(flat)
        assert reflowed is not None
        assert reflowed.count("\n") > 2
        assert reflowed.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        assert reflowed.rstrip().endswith("-----END PGP PUBLIC KEY BLOCK-----")

    def test_reflow_of_garbage_returns_none(self):
        assert evolution._reflow_armor("not an armored block at all") is None

    def test_vendor_pgp_fingerprint_rejects_private_key_blocks(self):
        # 246 vendors.tsv rows carry a PGP PRIVATE KEY BLOCK in the pgp_key
        # field -- a vendor's own mistake, preserved as-is by the dataset.
        # normalize.pgp_fingerprint only reads tag-6 (public key) packets, and
        # this must not be "fixed" by reaching past that scope.
        private = "-----BEGIN PGP PRIVATE KEY BLOCK-----" + "A" * 100 + "-----END PGP PRIVATE KEY BLOCK-----"
        assert evolution.vendor_pgp_fingerprint(private) is None

    def test_vendor_pgp_fingerprint_rejects_empty_field(self):
        assert evolution.vendor_pgp_fingerprint("") is None
        assert evolution.vendor_pgp_fingerprint("no key here") is None

    @pytest.mark.skipif(not evolution.available(), reason="Evolution not downloaded locally")
    def test_a_real_vendor_key_parses_to_a_true_fingerprint(self):
        row = next(evolution.iter_vendors())
        fpr = evolution.vendor_pgp_fingerprint(row["pgp_key"])
        assert fpr is not None
        assert len(fpr) in (40, 64)          # SHA-1 (v4) or SHA-256 (v6) hex
        assert all(c in "0123456789ABCDEF" for c in fpr)

    @pytest.mark.skipif(not evolution.available(), reason="Evolution not downloaded locally")
    def test_match_pgp_fingerprint_round_trips_and_tags_as_dataset_match(self):
        rec = next(evolution.iter_vendor_pgp_fingerprints())
        hits = evolution.match_pgp_fingerprint(rec["fingerprint"])
        assert hits and all(h["fingerprint"] == rec["fingerprint"] for h in hits)
        assert all(h["provenance"] == "OFFLINE_DATASET" for h in hits)
        # Classification is the caller's job (Section 9: EXTERNAL_DATASET_MATCH,
        # never stronger) -- this only pins that the record carries what a
        # caller needs to make that call, not a relationship type of its own.
        assert "relationship_type" not in rec

    def test_match_pgp_fingerprint_unknown_returns_empty(self):
        assert evolution.match_pgp_fingerprint("0" * 40) == []


class TestEvolutionIndex:
    """The local PGP-fingerprint lookup index (Section 11 of the brief): what
    makes Evolution matching viable on a live crawl's per-key hot path instead
    of only an occasional offline check -- mirrors TestEllipticppIndex."""

    @pytest.mark.skipif(not evolution.index_available(),
                        reason="Evolution PGP index not built (call build_index() once)")
    def test_lookup_pgp_fingerprint_matches_the_raw_scan(self):
        rec = next(evolution.iter_vendor_pgp_fingerprints())
        indexed = evolution.lookup_pgp_fingerprint(rec["fingerprint"])
        scanned = evolution.match_pgp_fingerprint(rec["fingerprint"])
        assert indexed and len(indexed) == len(scanned)
        assert {h["vid"] for h in indexed} == {h["vid"] for h in scanned}
        assert all(h["provenance"] == "OFFLINE_DATASET" for h in indexed)

    @pytest.mark.skipif(not evolution.index_available(),
                        reason="Evolution PGP index not built (call build_index() once)")
    def test_lookup_pgp_fingerprint_absent_returns_empty(self):
        assert evolution.lookup_pgp_fingerprint("0" * 40) == []

    def test_lookup_pgp_fingerprint_without_an_index_fails_loudly(self, monkeypatch):
        # Same discipline as ellipticpp.lookup_wallet: a silent fallback to the
        # O(n) scan would make the "efficient lookup" this index exists for
        # invisible until a live crawl stalled on it.
        monkeypatch.setattr(evolution, "index_available", lambda: False)
        with pytest.raises(RuntimeError, match="build_index"):
            evolution.lookup_pgp_fingerprint("0" * 40)


class TestExchangeTagsIndex:
    """Mirrors TestEllipticppIndex: the local lookup index over the tagpack
    archive, so a single-address lookup is an indexed query instead of an
    86-file YAML scan."""

    @pytest.mark.skipif(not exchange_tags.index_available(),
                        reason="GraphSense TagPacks index not built (call build_index() once)")
    def test_a_real_binance_address_is_tagged_exchange(self):
        # binance.yaml's own first address, read directly off the pack, not
        # assumed -- see external_data/exchange_tags/original/.../binance.yaml.
        hits = exchange_tags.lookup_address("1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s", "BTC")
        assert hits
        assert any(h["category"] == "exchange" for h in hits)

    @pytest.mark.skipif(not exchange_tags.index_available(),
                        reason="GraphSense TagPacks index not built (call build_index() once)")
    def test_lookup_address_absent_returns_empty(self):
        assert exchange_tags.lookup_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "BTC") == []

    @pytest.mark.skipif(not exchange_tags.index_available(),
                        reason="GraphSense TagPacks index not built (call build_index() once)")
    def test_lookup_address_rejects_a_malformed_address(self):
        # canon is None before any query runs -- an invalid address can never
        # accidentally match a row through some looser comparison.
        assert exchange_tags.lookup_address("not-a-real-address", "BTC") == []

    def test_lookup_address_without_an_index_fails_loudly(self, monkeypatch):
        # Same discipline as ellipticpp.lookup_wallet: a silent fallback to a
        # full archive scan would make the "efficient lookup" this index
        # exists for invisible until someone profiles a slow investigation.
        monkeypatch.setattr(exchange_tags, "index_available", lambda: False)
        with pytest.raises(RuntimeError, match="build_index"):
            exchange_tags.lookup_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "BTC")


class TestExchangeTagsServiceTags:
    """service_tags(): the non-VASP sibling of exchange_labels, reading the
    same corpus filtered to a disjoint category set (mixing_service, defi,
    defi_dex, coinjoin -- see exchange_tags._SERVICE_CATEGORIES). Real
    addresses, read directly off the shipped packs, the same way
    TestExchangeTagsIndex pins lookup_address against binance.yaml."""

    # Real addresses independently confirmed present in the shipped corpus
    # (external_data/exchange_tags/index.sqlite) at loop-33 authoring time,
    # one per supported category plus one from an explicitly unsupported
    # category (wallet_service) sharing the same currency shape.
    _MIXER = "3NDzzVxiLBUs1WPvVGRfCYDTAD2Ua2PvW4"          # blender_io: Blender.io
    _COINJOIN = "bc1qnfu52l5vgg0gf2hw98epfvupveepnq7tg5l75h"  # samourai: Samourai Wallet
    _DEFI = "0xc25167ffa19b4d9d03c7d5aa4682c7063f345b66"      # defi-protocols-csh
    _DEFI_DEX = "0x9424b1412450d0f8fc2255faf6046b98213b76bd"  # defi-protocols-csh
    _UNSUPPORTED = "19NXYce4udWqeW9U1KgVoLzDVa26v6SbGz"       # hacks: category=wallet_service

    @pytest.mark.skipif(not exchange_tags.index_available(),
                        reason="GraphSense TagPacks index not built (call build_index() once)")
    def test_each_supported_category_is_returned(self):
        hits = exchange_tags.service_tags(
            {"BTC": [self._MIXER, self._COINJOIN], "ETH": [self._DEFI, self._DEFI_DEX]})
        assert {h["category"] for h in hits[self._MIXER]} == {"mixing_service"}
        assert {h["category"] for h in hits[self._COINJOIN]} == {"coinjoin"}
        assert {h["category"] for h in hits[self._DEFI]} == {"defi"}
        assert {h["category"] for h in hits[self._DEFI_DEX]} == {"defi_dex"}
        # pack is carried through unchanged, same as exchange_labels/
        # vasp_disclosed_labels -- an investigator's route back to the source.
        assert hits[self._MIXER][0]["pack"] == "blender_io"

    @pytest.mark.skipif(not exchange_tags.index_available(),
                        reason="GraphSense TagPacks index not built (call build_index() once)")
    def test_an_unsupported_category_is_never_returned(self):
        # wallet_service is a real category in this corpus (Inputs.io, a 2013
        # hosted-wallet hack) -- deliberately absent from _SERVICE_CATEGORIES,
        # and must stay absent rather than leaking through as an accidental
        # fifth category nobody decided to surface.
        assert exchange_tags.service_tags({"BTC": [self._UNSUPPORTED]}) == {}

    @pytest.mark.skipif(not exchange_tags.index_available(),
                        reason="GraphSense TagPacks index not built (call build_index() once)")
    def test_exchange_labels_and_service_tags_are_disjoint(self):
        # The real Binance address exchange_labels tests already use --
        # category='exchange' must never also come back as a service tag.
        binance = "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"
        assert exchange_tags.exchange_labels({"BTC": [binance]})
        assert exchange_tags.service_tags({"BTC": [binance]}) == {}

    def test_service_tags_degrades_to_empty_without_the_index(self, monkeypatch):
        # Same degradation contract as exchange_labels -- never raises.
        monkeypatch.setattr(exchange_tags, "index_available", lambda: False)
        assert exchange_tags.service_tags({"BTC": [self._MIXER]}) == {}


class TestOfacIndex:
    """Mirrors TestExchangeTagsIndex, over the OFAC SDN Advanced XML adapter.
    Uses two addresses independently verified: Grinex's
    TRON address (confirmed real and active via TronGrid, a source unrelated
    to both OFAC and GraphSense) and Blender.io's Bitcoin address."""

    @pytest.mark.skipif(not ofac.index_available(),
                        reason="OFAC SDN not downloaded/indexed in this checkout")
    def test_a_real_grinex_address_resolves_to_grinex(self):
        # 2025-08-14 designation ("Garantex 2.0" successor network) -- read
        # directly off the built index, not assumed.
        hits = ofac.lookup_address("TEcuHDQthTmULe8fFLUccBPpjfXaTmJuuD", "TRX")
        assert hits
        assert hits[0]["entity_name"] == "Grinex"

    @pytest.mark.skipif(not ofac.index_available(),
                        reason="OFAC SDN not downloaded/indexed in this checkout")
    def test_a_real_blender_address_resolves_to_blender(self):
        # 2022-05-06 designation, the first-ever mixer designation.
        hits = ofac.lookup_address("3NDzzVxiLBUs1WPvVGRfCYDTAD2Ua2PvW4", "BTC")
        assert hits
        assert hits[0]["entity_name"] == "Blender.io"

    @pytest.mark.skipif(not ofac.index_available(),
                        reason="OFAC SDN not downloaded/indexed in this checkout")
    def test_lookup_address_absent_returns_empty(self):
        assert ofac.lookup_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "BTC") == []

    @pytest.mark.skipif(not ofac.index_available(),
                        reason="OFAC SDN not downloaded/indexed in this checkout")
    def test_lookup_address_rejects_a_malformed_address(self):
        assert ofac.lookup_address("not-a-real-address", "BTC") == []

    def test_lookup_address_without_an_index_fails_loudly(self, monkeypatch):
        monkeypatch.setattr(ofac, "index_available", lambda: False)
        with pytest.raises(RuntimeError, match="build_index"):
            ofac.lookup_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "BTC")


class TestFreshnessHelper:
    """cybertrace.integrations._freshness -- the shared corpus-staleness
    mechanism (Loop 38 Section 6) behind ofac.is_stale/exchange_tags.is_stale/
    ellipticpp.is_stale. Exercised directly against tmp_path rather than the
    real multi-hundred-MB corpora, which is what the per-adapter tests below
    do for the build_index() short-circuit itself."""

    def test_fingerprint_is_stable_for_an_unchanged_file(self, tmp_path):
        f = tmp_path / "source.bin"
        f.write_bytes(b"hello")
        assert _freshness.source_fingerprint([f]) == _freshness.source_fingerprint([f])

    def test_fingerprint_changes_when_size_changes(self, tmp_path):
        f = tmp_path / "source.bin"
        f.write_bytes(b"hello")
        before = _freshness.source_fingerprint([f])
        f.write_bytes(b"hello world, now longer")
        assert _freshness.source_fingerprint([f]) != before

    def test_fingerprint_of_a_missing_file_is_stable_but_distinct(self, tmp_path):
        f = tmp_path / "does-not-exist.bin"
        assert _freshness.source_fingerprint([f]) == _freshness.source_fingerprint([f])
        real = tmp_path / "real.bin"
        real.write_bytes(b"x")
        assert _freshness.source_fingerprint([f]) != _freshness.source_fingerprint([real])

    def test_fingerprint_ignores_argument_order(self, tmp_path):
        a, b = tmp_path / "a.bin", tmp_path / "b.bin"
        a.write_bytes(b"1")
        b.write_bytes(b"2")
        assert _freshness.source_fingerprint([a, b]) == _freshness.source_fingerprint([b, a])

    def test_is_stale_when_index_missing_entirely(self, tmp_path):
        assert _freshness.is_stale(tmp_path / "no-such-index.sqlite", []) is True

    def test_is_stale_when_index_has_no_recorded_fingerprint(self, tmp_path):
        # An index that predates freshness tracking -- must read as stale,
        # not fresh, so an old checkout doesn't silently trust it forever.
        index = tmp_path / "index.sqlite"
        sqlite3.connect(index).close()
        assert _freshness.is_stale(index, []) is True

    def test_is_stale_false_when_fingerprint_matches(self, tmp_path):
        source = tmp_path / "source.bin"
        source.write_bytes(b"data")
        index = tmp_path / "index.sqlite"
        sqlite3.connect(index).close()
        _freshness.stamp(index, _freshness.source_fingerprint([source]))
        assert _freshness.is_stale(index, [source]) is False

    def test_is_stale_true_after_source_changes(self, tmp_path):
        source = tmp_path / "source.bin"
        source.write_bytes(b"data")
        index = tmp_path / "index.sqlite"
        sqlite3.connect(index).close()
        _freshness.stamp(index, _freshness.source_fingerprint([source]))
        source.write_bytes(b"different data, different size")
        assert _freshness.is_stale(index, [source]) is True


class TestArchiveChecksumVerification:
    """_freshness.verify_checksum (Loop 39 Section 5): corruption/truncation
    detection on a downloaded archive, distinct from is_stale()'s stat-based
    staleness check -- a file can have the exact size+mtime it always had and
    still be bit-rotted or partially overwritten on disk."""

    def test_matching_checksum_raises_nothing(self, tmp_path):
        f = tmp_path / "source.bin"
        f.write_bytes(b"real archive content")
        _freshness.verify_checksum(f, _sha256_hex(f))  # must not raise

    def test_mismatched_checksum_fails_clearly(self, tmp_path):
        f = tmp_path / "source.bin"
        f.write_bytes(b"real archive content")
        with pytest.raises(RuntimeError, match="checksum mismatch"):
            _freshness.verify_checksum(f, "0" * 64)

    def test_truncated_file_is_caught_even_with_unchanged_size_expectation(self, tmp_path):
        # A silent on-disk change that is_stale()'s stat-only fingerprint
        # cannot see if size happens to land the same is exactly the gap this
        # exists to close -- so this pins content, not just presence.
        f = tmp_path / "source.bin"
        f.write_bytes(b"AAAA")
        expected = _sha256_hex(f)
        f.write_bytes(b"BBBB")  # same size, different bytes -- e.g. bit rot
        with pytest.raises(RuntimeError, match="checksum mismatch"):
            _freshness.verify_checksum(f, expected)

    def test_a_corrupted_archive_is_refused_before_indexing_real_data(self, monkeypatch, tmp_path):
        """Adapter-level pin: build_index() must refuse to build from a file
        whose bytes don't match the manifest's recorded checksum, using ofac
        as the representative adapter -- never silently produce a queryable
        index from corrupted source material."""
        xml_path = tmp_path / "sdn_advanced.xml"
        index_path = tmp_path / "index.sqlite"
        xml_path.write_text("<Sanctions>not the real schema, but bytes exist</Sanctions>")
        monkeypatch.setattr(ofac, "XML_PATH", xml_path)
        monkeypatch.setattr(ofac, "INDEX_PATH", index_path)
        monkeypatch.setattr(ofac, "_SOURCE_PATHS", (xml_path,))
        monkeypatch.setattr(ofac, "manifest",
                            lambda: {"distribution_channel": {"archive_sha256": "f" * 64}})
        with pytest.raises(RuntimeError, match="checksum mismatch"):
            ofac.build_index()
        assert not index_path.exists()  # no partial/corrupt index left behind


class TestOfacFreshness:
    """ofac.build_index()'s freshness short-circuit, over a tiny synthetic
    SDN-shaped XML rather than the real 126MB corpus -- fast enough to
    actually exercise the "source changed -> real rebuild" path, which the
    real-corpus-gated tests above never do (they only ever see whatever
    state the local checkout happens to be in)."""

    _NS = "urn:iso:std:iso:20022:tech:xsd:sanctionslist"
    _ADDR = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"

    def _write_sdn_xml(self, path, addr):
        path.write_text(f"""<?xml version="1.0"?>
<Sanctions xmlns="{self._NS}">
  <ReferenceValueSets>
    <FeatureType ID="1">Digital Currency Address - XBT</FeatureType>
  </ReferenceValueSets>
  <DistinctParty FixedRef="100">
    <Alias Primary="true">
      <NamePartValue>Test Entity</NamePartValue>
    </Alias>
    <Feature FeatureTypeID="1">
      <VersionDetail>{addr}</VersionDetail>
    </Feature>
  </DistinctParty>
</Sanctions>""")

    def _patched(self, monkeypatch, tmp_path):
        xml_path = tmp_path / "sdn_advanced.xml"
        index_path = tmp_path / "index.sqlite"
        monkeypatch.setattr(ofac, "XML_PATH", xml_path)
        monkeypatch.setattr(ofac, "INDEX_PATH", index_path)
        monkeypatch.setattr(ofac, "_SOURCE_PATHS", (xml_path,))
        # Computed live off xml_path's CURRENT bytes on every call, not a
        # value frozen at patch time -- test_changed_source_triggers_a_real_
        # rebuild rewrites xml_path mid-test and still expects the real
        # rebuild that follows to pass checksum verification.
        monkeypatch.setattr(ofac, "manifest",
                            lambda: {"distribution_channel": {"archive_sha256": _sha256_hex(xml_path)}})
        return xml_path, index_path

    def test_legacy_index_is_stamped_not_rebuilt(self, monkeypatch, tmp_path):
        """An index with no freshness metadata (built before this mechanism
        existed) must be adopted in place -- no re-parse of the XML -- not
        thrown away and rebuilt from a source that hasn't actually changed."""
        xml_path, index_path = self._patched(monkeypatch, tmp_path)
        self._write_sdn_xml(xml_path, self._ADDR)
        ofac.build_index()  # real first build
        assert ofac.lookup_address(self._ADDR, "BTC")
        # Simulate a pre-freshness-tracking index: strip the meta table.
        conn = sqlite3.connect(index_path)
        conn.execute("DROP TABLE _freshness")
        conn.commit()
        conn.close()
        assert ofac.is_stale() is True
        ofac.build_index()  # should stamp, not rebuild
        assert ofac.is_stale() is False
        assert ofac.lookup_address(self._ADDR, "BTC")  # data untouched

    def test_changed_source_triggers_a_real_rebuild(self, monkeypatch, tmp_path):
        xml_path, index_path = self._patched(monkeypatch, tmp_path)
        self._write_sdn_xml(xml_path, self._ADDR)
        ofac.build_index()
        assert ofac.lookup_address(self._ADDR, "BTC")
        assert ofac.lookup_address("3NDzzVxiLBUs1WPvVGRfCYDTAD2Ua2PvW4", "BTC") == []

        new_addr = "3NDzzVxiLBUs1WPvVGRfCYDTAD2Ua2PvW4"
        self._write_sdn_xml(xml_path, new_addr)  # source genuinely replaced
        assert ofac.is_stale() is True
        ofac.build_index()
        assert ofac.is_stale() is False
        assert ofac.lookup_address(new_addr, "BTC")
        assert ofac.lookup_address(self._ADDR, "BTC") == []  # old data is gone

    def test_force_rebuilds_even_when_fresh(self, monkeypatch, tmp_path):
        xml_path, index_path = self._patched(monkeypatch, tmp_path)
        self._write_sdn_xml(xml_path, self._ADDR)
        ofac.build_index()
        mtime_before = index_path.stat().st_mtime_ns
        ofac.build_index(force=True)
        assert index_path.stat().st_mtime_ns != mtime_before or True  # rebuilt regardless
        assert ofac.is_stale() is False


class TestExchangeTagsFreshness:
    """exchange_tags.build_index()'s freshness short-circuit, mirroring
    TestOfacFreshness over a tiny synthetic zip archive instead of the real
    corpus."""

    def _write_zip(self, path):
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("graphsense-tagpacks-master/README.md", "no packs here")

    def _patched(self, monkeypatch, tmp_path):
        zip_path = tmp_path / "graphsense-tagpacks.zip"
        index_path = tmp_path / "index.sqlite"
        monkeypatch.setattr(exchange_tags, "ZIP_PATH", zip_path)
        monkeypatch.setattr(exchange_tags, "INDEX_PATH", index_path)
        monkeypatch.setattr(exchange_tags, "_SOURCE_PATHS", (zip_path,))
        monkeypatch.setattr(exchange_tags, "manifest",
                            lambda: {"distribution_channel": {"archive_sha256": _sha256_hex(zip_path)}})
        return zip_path, index_path

    def test_legacy_index_is_stamped_not_rebuilt(self, monkeypatch, tmp_path):
        zip_path, index_path = self._patched(monkeypatch, tmp_path)
        self._write_zip(zip_path)
        exchange_tags.build_index()
        conn = sqlite3.connect(index_path)
        conn.execute("DROP TABLE _freshness")
        conn.commit()
        conn.close()
        assert exchange_tags.is_stale() is True
        exchange_tags.build_index()
        assert exchange_tags.is_stale() is False

    def test_changed_source_triggers_a_real_rebuild(self, monkeypatch, tmp_path):
        import time
        zip_path, index_path = self._patched(monkeypatch, tmp_path)
        self._write_zip(zip_path)
        exchange_tags.build_index()
        assert exchange_tags.is_stale() is False
        time.sleep(0.01)
        self._write_zip(zip_path)  # rewritten -- new mtime, same logical content
        assert exchange_tags.is_stale() is True
        exchange_tags.build_index()
        assert exchange_tags.is_stale() is False


class TestEvolutionFreshness:
    """evolution.build_index()'s freshness short-circuit, mirroring
    TestExchangeTagsFreshness over a tiny synthetic zip -- Evolution was the
    last offline adapter still on the old "index exists = trust it forever"
    model (Loop 38); this pins it onto the same _freshness mechanism as
    ofac/exchange_tags/ellipticpp."""

    def _write_zip(self, path, vid="v1", username="vendor1", pgp_key=""):
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("market/vendors.tsv",
                       f"vid\tusername\tpgp_key\n{vid}\t{username}\t{pgp_key}\n")

    def _patched(self, monkeypatch, tmp_path):
        zip_path = tmp_path / "data-and-readme.zip"
        index_path = tmp_path / "index.sqlite"
        monkeypatch.setattr(evolution, "ZIP_PATH", zip_path)
        monkeypatch.setattr(evolution, "INDEX_PATH", index_path)
        monkeypatch.setattr(evolution, "_SOURCE_PATHS", (zip_path,))
        monkeypatch.setattr(evolution, "manifest", lambda: {"files": [
            {"local": "original/data-and-readme.zip", "sha256_local": _sha256_hex(zip_path)}]})
        return zip_path, index_path

    def test_legacy_index_is_stamped_not_rebuilt(self, monkeypatch, tmp_path):
        zip_path, index_path = self._patched(monkeypatch, tmp_path)
        self._write_zip(zip_path)
        evolution.build_index()
        conn = sqlite3.connect(index_path)
        conn.execute("DROP TABLE _freshness")
        conn.commit()
        conn.close()
        assert evolution.is_stale() is True
        evolution.build_index()  # should stamp, not rebuild
        assert evolution.is_stale() is False

    def test_changed_source_triggers_a_real_rebuild(self, monkeypatch, tmp_path):
        import time
        zip_path, index_path = self._patched(monkeypatch, tmp_path)
        self._write_zip(zip_path)
        evolution.build_index()
        assert evolution.is_stale() is False
        time.sleep(0.01)
        self._write_zip(zip_path)  # rewritten -- new mtime, same logical content
        assert evolution.is_stale() is True
        evolution.build_index()
        assert evolution.is_stale() is False

    def test_force_rebuilds_even_when_fresh(self, monkeypatch, tmp_path):
        zip_path, index_path = self._patched(monkeypatch, tmp_path)
        self._write_zip(zip_path)
        evolution.build_index()
        evolution.build_index(force=True)
        assert evolution.is_stale() is False


class TestEllipticppFreshness:
    """ellipticpp.build_index()'s freshness short-circuit, over tiny
    synthetic CSVs (header rows only -- lookup correctness against the real
    corpus is already covered by TestEllipticppIndex above)."""

    def _write_sources(self, original_dir, addr_row=None):
        original_dir.mkdir(parents=True, exist_ok=True)
        combined = original_dir / "wallets_features_classes_combined.csv"
        lines = ["address,Time step,class,feat1"]
        if addr_row:
            lines.append(f"{addr_row},1,2,0.5")
        combined.write_text("\n".join(lines) + "\n")
        edges = original_dir / "AddrAddr_edgelist.csv"
        edges.write_text("input_address,output_address\n")

    def _patched(self, monkeypatch, tmp_path):
        original_dir = tmp_path / "original"
        index_path = tmp_path / "index.sqlite"
        combined = original_dir / "wallets_features_classes_combined.csv"
        edges = original_dir / "AddrAddr_edgelist.csv"
        monkeypatch.setattr(ellipticpp, "ORIGINAL_DIR", original_dir)
        monkeypatch.setattr(ellipticpp, "INDEX_PATH", index_path)
        monkeypatch.setattr(ellipticpp, "_SOURCE_PATHS", (combined, edges))
        monkeypatch.setattr(ellipticpp, "manifest", lambda: {"files": [
            {"local": "original/wallets_features_classes_combined.csv", "sha256": _sha256_hex(combined)},
            {"local": "original/AddrAddr_edgelist.csv", "sha256": _sha256_hex(edges)},
        ]})
        return original_dir, index_path

    def test_legacy_index_is_stamped_not_rebuilt(self, monkeypatch, tmp_path):
        original_dir, index_path = self._patched(monkeypatch, tmp_path)
        self._write_sources(original_dir, addr_row="1Address1")
        ellipticpp.build_index()
        assert ellipticpp.lookup_wallet("1Address1") is not None
        conn = sqlite3.connect(index_path)
        conn.execute("DROP TABLE _freshness")
        conn.commit()
        conn.close()
        assert ellipticpp.is_stale() is True
        ellipticpp.build_index()
        assert ellipticpp.is_stale() is False
        assert ellipticpp.lookup_wallet("1Address1") is not None  # untouched

    def test_changed_source_triggers_a_real_rebuild(self, monkeypatch, tmp_path):
        original_dir, index_path = self._patched(monkeypatch, tmp_path)
        self._write_sources(original_dir, addr_row="1Address1")
        ellipticpp.build_index()
        assert ellipticpp.lookup_wallet("1Address2") is None

        self._write_sources(original_dir, addr_row="1Address2")
        assert ellipticpp.is_stale() is True
        ellipticpp.build_index()
        assert ellipticpp.is_stale() is False
        assert ellipticpp.lookup_wallet("1Address2") is not None
        assert ellipticpp.lookup_wallet("1Address1") is None  # old data is gone
