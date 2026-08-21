"""Offline research/evaluation adapters over external datasets.

Everything here is read-only against external_data/<dataset>/original/ (never
mutated) and stays OUT of the live investigation pipeline: no adapter here
imports EvidenceStore, ingest(), or the enrichment routers in evidence.py, and
none should be added without an explicit decision documented the way
evidence.py:270 documents CERTIFICATE staying unwired. Records carry the
source dataset's own label as `dataset_label` -- a research annotation, never
an operator claim about any CyberTrace target. See each module's docstring
and tests/test_integrations.py for the enforced boundary.
"""
