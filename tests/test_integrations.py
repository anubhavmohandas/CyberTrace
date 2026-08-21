"""Offline dataset adapters (Elliptic++, Evolution): provenance + the one
invariant that actually matters -- a dataset label can never reach the live
EvidenceStore/ingest() path. See cybertrace/integrations/*.py docstrings."""

import inspect

import pytest

from cybertrace.integrations import ellipticpp, evolution


class TestEvidenceStoreIsUnreachable:
    """Pins the safety boundary directly against the source, not just against
    behavior today -- a future edit that imports EvidenceStore into either
    adapter must fail this test, the same way evidence.py:270 documents
    CERTIFICATE staying unwired rather than leaving it to be noticed later."""

    @pytest.mark.parametrize("module", [ellipticpp, evolution])
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
