"""Offline dataset adapters (Elliptic++, Evolution, GraphSense TagPacks):
provenance + the one invariant that actually matters -- a dataset label can
never reach the live EvidenceStore/ingest() path. See
cybertrace/integrations/*.py docstrings."""

import inspect

import pytest

from cybertrace.integrations import ellipticpp, evolution, exchange_tags


class TestEvidenceStoreIsUnreachable:
    """Pins the safety boundary directly against the source, not just against
    behavior today -- a future edit that imports EvidenceStore into any
    adapter must fail this test, the same way evidence.py:270 documents
    CERTIFICATE staying unwired rather than leaving it to be noticed later."""

    @pytest.mark.parametrize("module", [ellipticpp, evolution, exchange_tags])
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
