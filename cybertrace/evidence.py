"""Persistent evidence store: the canonical model every other layer reads from.

    Target -> Snapshot -> Observation -> Entity
    Relationship -> Evidence(observation ids) -> Snapshot sha256
    Finding    investigative conclusion (CLONE_SUSPECT, SUCCESSOR_CANDIDATE)

Two properties make this different from dumping scraped values into a table:

**Provenance.** Every relationship resolves through evidence to the exact
observations that support it, and each observation to a hashed, timestamped
snapshot. Any claim the tool makes can be walked back to the bytes it came
from — that is the line between an OSINT result and auditable evidence.

**Identity before correlation.** An entity is unique by
(etype, normalized_value) and normalization happens at write time, so the
correlation layer never reconciles duplicates or matches on unvalidated junk.

Existing modules need no rewrite: `ingest()` adapts a ModuleResult (or its
saved dict) into this model, so any module that already emits SourceResults
becomes an evidence producer by being routed here.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .normalize import normalize, simhash_similarity

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS targets (
  target_id  TEXT PRIMARY KEY,
  url        TEXT NOT NULL UNIQUE,
  kind       TEXT NOT NULL,                 -- ONION | CLEARNET
  label      TEXT,
  first_seen TEXT NOT NULL,
  last_seen  TEXT,
  active     INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS snapshots (
  snapshot_id          TEXT PRIMARY KEY,
  target_id            TEXT NOT NULL REFERENCES targets(target_id),
  observed_at          TEXT NOT NULL,
  collector            TEXT NOT NULL,
  sha256               TEXT NOT NULL,       -- hash of the payload below
  payload              TEXT,                -- canonical JSON of what was collected
  raw_path             TEXT,                -- optional: retained HTML/headers on disk
  previous_snapshot_id TEXT,
  diff_summary         TEXT,
  status               TEXT DEFAULT 'OK'
);

-- Canonical dedup point for the whole system.
CREATE TABLE IF NOT EXISTS entities (
  entity_id        TEXT PRIMARY KEY,
  etype            TEXT NOT NULL,
  normalized_value TEXT NOT NULL,
  raw_value        TEXT,
  metadata         TEXT,                    -- JSON: ip_class, key role, ...
  first_seen       TEXT,
  last_seen        TEXT,
  UNIQUE (etype, normalized_value)
);

CREATE TABLE IF NOT EXISTS observations (
  observation_id    TEXT PRIMARY KEY,
  snapshot_id       TEXT NOT NULL REFERENCES snapshots(snapshot_id),
  entity_id         TEXT NOT NULL REFERENCES entities(entity_id),
  extraction_method TEXT NOT NULL,
  section           TEXT,
  context           TEXT,                   -- snippet a human can check
  confidence        REAL DEFAULT 0.7,
  observed_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS relationships (
  rel_id           TEXT PRIMARY KEY,
  source_entity_id TEXT NOT NULL REFERENCES entities(entity_id),
  target_entity_id TEXT NOT NULL REFERENCES entities(entity_id),
  rtype            TEXT NOT NULL,
  source_label     TEXT,
  first_seen       TEXT,
  last_seen        TEXT,
  weight           REAL,
  status           TEXT DEFAULT 'ACTIVE',
  UNIQUE (source_entity_id, target_entity_id, rtype)
);

CREATE TABLE IF NOT EXISTS evidence (
  evidence_id     TEXT PRIMARY KEY,
  relationship_id TEXT REFERENCES relationships(rel_id),
  observation_ids TEXT NOT NULL,            -- JSON array
  note            TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  finding_id   TEXT PRIMARY KEY,
  ftype        TEXT NOT NULL,
  description  TEXT NOT NULL,
  severity     TEXT DEFAULT 'MEDIUM',
  confidence   REAL,
  status       TEXT DEFAULT 'OPEN',
  evidence_ids TEXT,                        -- JSON array
  created_at   TEXT,
  updated_at   TEXT
);

CREATE TABLE IF NOT EXISTS candidates (
  candidate_id      TEXT PRIMARY KEY,
  ctype             TEXT NOT NULL,          -- OPERATOR | INFRA | IP
  entity_id         TEXT REFERENCES entities(entity_id),
  confidence        REAL,
  assessment        TEXT,
  supporting_ids    TEXT,                   -- JSON array of evidence_id
  contradicting_ids TEXT,                   -- JSON array; clone evidence goes HERE
  updated_at        TEXT
);

CREATE INDEX IF NOT EXISTS idx_snap_target ON snapshots(target_id);
CREATE INDEX IF NOT EXISTS idx_ent_type    ON entities(etype);
CREATE INDEX IF NOT EXISTS idx_obs_snap    ON observations(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_obs_entity  ON observations(entity_id);
CREATE INDEX IF NOT EXISTS idx_rel_source  ON relationships(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_rel_target  ON relationships(target_entity_id);
CREATE INDEX IF NOT EXISTS idx_rel_type    ON relationships(rtype);
"""

ENTITY_TYPES = {
    "MARKET", "ONION_ADDRESS", "PAGE", "DOCUMENT",
    "OPERATOR_CANDIDATE", "USERNAME", "EMAIL", "PGP_KEY", "PHONE",
    "TELEGRAM", "SESSION_ID",
    "BTC_ADDRESS", "XMR_ADDRESS", "ETH_ADDRESS", "CRYPTO_CLUSTER", "EXCHANGE",
    "IP", "ASN", "HOSTING_PROVIDER", "VPN_PROVIDER", "DOMAIN",
    "NAMESERVER", "CERTIFICATE", "FAVICON", "HTTP_FINGERPRINT", "ANALYTICS_ID",
    "SOCIAL_ACCOUNT", "FORUM_ACCOUNT", "BREACH_RECORD",
}

RELATIONSHIP_TYPES = {
    "HAS_ADDRESS", "HAS_PAGE", "CONTAINS", "MENTIONS",
    "USES_PGP", "USES_EMAIL", "USES_USERNAME", "USES_TELEGRAM", "USES_PHONE",
    "SIGNS_WITH", "ASSOCIATED_WITH",
    "USES_BTC", "USES_XMR", "USES_ETH", "PART_OF_CLUSTER",
    "HOSTED_ON", "RESOLVES_TO", "BELONGS_TO_ASN", "OWNED_BY",
    "USES_CERT", "USES_NS", "USES_ANALYTICS", "CANDIDATE_IP", "LINKS_TO",
    "HAS_FINGERPRINT",
    "COPIES", "CROSS_SIGNS", "SIGNED_BY", "SIMILAR_TO", "SUCCESSOR_OF",
    "LINKED_TO", "ASSOCIATED_WITH_IP", "DISCOVERED_VIA",
}

# Directional conventions worth stating once, because reading them backwards
# inverts an attribution:
#
#   SIGNED_BY       signer -> signed key. The source key's holder certified the
#                   target key. Written from certification packets inside a
#                   published key block (normalize.pgp_certifiers).
#   SIGNS_WITH      market -> key, where the page carried a signature that key
#                   issued. Distinct from USES_PGP (market -> key merely shown),
#                   because only the signature needs the secret half.
#   DISCOVERED_VIA  market -> onion that an INDEX returned beside it. NOT a link
#                   the market published; it carries no funnel weight and exists
#                   so "Torch ranked these together" stays distinguishable from
#                   "this market links there".
#   PART_OF_CLUSTER address -> address co-spent in one transaction (undirected in
#                   meaning; correlate takes connected components).

IP_CLASSES = {"INFRA_IP", "PERSONAL_IP", "VPN_IP", "EXCHANGE_IP", "UNKNOWN"}

# Netblock owners that are anonymity egress rather than origin hosting. The
# distinction changes the next investigative step, not the score: for a tunnel
# exit the subscriber logs may never have existed, so a candidate built on one
# needs that caveat before anyone files for retention.
# occam: substring match on netblock owner. Swap for an ASN lookup against a
# maintained VPN/hosting dataset once a corpus shows exits this list misses.
_VPN_ORGS = ("nordvpn", "expressvpn", "mullvad", "protonvpn", "surfshark",
             "cyberghost", "windscribe", "ivpn", "private internet access",
             "vpn", "tor exit")


def classify_ip(org: str, isp: Optional[str] = None,
                flags: Optional[dict] = None) -> str:
    """Classify a host, preferring the enrichment source's own flags.

    ip-api resolves proxy/hosting from its own dataset, so when that ran its
    verdict is real evidence and outranks anything read off a company name. The
    name match is only the fallback for the favicon->Shodan path, which returns
    an owner string and nothing else.

    Everything unmatched stays UNKNOWN on purpose: an org name alone cannot
    separate a rented VPS from a residential line, and guessing that difference
    is how an investigation attributes a market to the wrong address.
    """
    flags = flags or {}
    if flags.get("is_tor") or flags.get("is_proxy"):
        return "VPN_IP"
    if flags.get("is_hosting"):
        return "INFRA_IP"
    haystack = f"{org or ''} {isp or ''}".lower()
    return "VPN_IP" if any(k in haystack for k in _VPN_ORGS) else "UNKNOWN"

# Which SourceResult.data keys carry which artifacts, and the edge each earns
# from the target. The one place the collector vocabulary meets the graph
# vocabulary — a new extractor becomes ingestable by adding a row here.
ARTIFACT_MAP = {
    "emails":                    ("EMAIL", "USES_EMAIL"),
    "bitcoin_addresses":         ("BTC_ADDRESS", "USES_BTC"),
    "monero_addresses":          ("XMR_ADDRESS", "USES_XMR"),
    "ethereum_addresses":        ("ETH_ADDRESS", "USES_ETH"),
    "clearnet_hosts_referenced": ("DOMAIN", "MENTIONS"),
    "onion_addresses_found":     ("ONION_ADDRESS", "LINKS_TO"),
    "analytics_ids":             ("ANALYTICS_ID", "USES_ANALYTICS"),
    "candidate_operator_ips":    ("IP", "CANDIDATE_IP"),
    "leaked_public_ipv4":        ("IP", "HOSTED_ON"),
    "usernames":                 ("USERNAME", "USES_USERNAME"),
}


# Server banners so common they identify nothing. A fingerprint made only of
# these must not become an entity: it would put every nginx market on one shared
# node and hand correlation a fleet of operator candidates whose sole connection
# is running the same web server — the exact shared-infrastructure noise a
# fingerprint is meant to cut through. A hand-written banner is the opposite: it
# is close to a build signature, and operators rarely think to change it.
_GENERIC_BANNER = re.compile(
    r"(nginx|apache2?|httpd|caddy|cloudflare|litespeed|iis|openresty|jetty|"
    r"gunicorn|werkzeug|express|php|asp\.net|node(\.js)?|tornado|kestrel)"
    r"[/ ]?[\d.]*$", re.I)


def fingerprint_signature(fp: dict) -> Optional[str]:
    """Canonical identity for an HTTP fingerprint, or None if it distinguishes
    nothing. Two markets built by one operator collapse onto a single node here.

    Volatile fields must stay out of the identity or nothing ever matches twice:
    clock skew and Date live beside this in the payload and are deliberately not
    read. Lists are sorted so header ordering between visits cannot fork a node.

    occam: substring-free exact-ish banner match, no commonness model. If a
    corpus shows generic banners still merging markets, weight by how many
    distinct targets share the signature instead of judging the string.
    """
    if not isinstance(fp, dict):
        return None
    fields = {k: sorted(map(str, v)) if isinstance(v, (list, tuple)) else str(v)
              for k, v in fp.items() if v}
    distinctive = any(not _GENERIC_BANNER.fullmatch(v.strip())
                      for v in fields.values() if isinstance(v, str))
    return _canon_json(fields) if distinctive and fields else None


# Collectors that search an index *for* the target instead of observing it. Only
# target_onion and operator_pivot actually fetch the site, so only they can say
# what it links to. A search result list says two onions ranked together and
# nothing more — ingesting that as LINKS_TO gives any two markets that co-rank
# beside the same link directory a shared node, which correlation then reads as
# an operator link. The failure is loudest when the target is DOWN: the visit
# fails, the index still answers, and the market's whole neighbourhood is noise.
_INDEX_SOURCES = {"ahmia", "torch", "dargle", "intelx", "onion_directories",
                  "paste_sites", "ransomwhat", "onion_lookup"}


# Collectors that actually visit the site, so their failure says something about
# the site rather than about an index.
_SITE_COLLECTORS = {"target_onion", "operator_pivot", "watch"}


def _site_was_down(error: Optional[str]) -> bool:
    """True when a failed visit is evidence about the SITE, not about us.

    The collector deliberately separates the two errors, and the difference is
    load-bearing here: 'Tor is not running' says our proxy is off and implies
    nothing about the target, while recording it as a down site would let a
    local misconfiguration manufacture the takedown that a successor hypothesis
    then explains.
    """
    text = (error or "").lower()
    return "unreachable" in text and "tor is not running" not in text


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canon_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))


# Fields that differ on every visit no matter what the site did. They stay in
# the stored payload — clock skew is a real correlation signal — and are simply
# not part of the question "did this page change".
_VOLATILE_FIELDS = frozenset({"clock_skew_seconds"})


def _stable(payload: Any) -> Any:
    """A payload with per-visit noise removed, for change detection only."""
    if isinstance(payload, dict):
        return {k: _stable(v) for k, v in payload.items() if k not in _VOLATILE_FIELDS}
    if isinstance(payload, list):
        return [_stable(v) for v in payload]
    return payload


class EvidenceStore:
    """SQLite-backed evidence store. All upserts are idempotent: re-ingesting a
    result updates last_seen instead of duplicating entities or edges."""

    def __init__(self, db_path: str = "cybertrace.db"):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        # (etype, raw) -> times normalization refused it. Extractor precision is
        # valid/extracted, and the store otherwise keeps only the numerator: a
        # rejected value leaves no row anywhere, so without this the denominator
        # is unrecoverable from the DB or the saved JSON.
        # occam: in-memory, per-instance, not a table — an audit ingests and
        # reads in one process. Persist it if rejects ever need trending.
        self.rejected: Counter = Counter()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @staticmethod
    def _id(prefix: str, seed: str = "") -> str:
        """Deterministic id where a row must dedup, random where it must not.
        A second sighting of one key is a NEW observation but the SAME entity."""
        if seed:
            return f"{prefix}_{hashlib.sha256(seed.encode()).hexdigest()[:16]}"
        return f"{prefix}_{uuid.uuid4().hex[:16]}"

    def _one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchone()

    def _all(self, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    # --- targets & snapshots -------------------------------------------------

    def upsert_target(self, url: str, label: Optional[str] = None) -> str:
        url = url.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
        kind = "ONION" if url.split("/")[0].endswith(".onion") else "CLEARNET"
        tid = self._id("tgt", url)
        now = utcnow()
        self.conn.execute(
            "INSERT INTO targets (target_id, url, kind, label, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(url) DO UPDATE SET last_seen=excluded.last_seen, "
            "label=COALESCE(targets.label, excluded.label)",
            (tid, url, kind, label, now, now),
        )
        self.conn.commit()
        return tid

    def insert_snapshot(self, target_id: str, payload: Any, collector: str,
                        observed_at: Optional[str] = None,
                        raw_path: Optional[str] = None) -> str:
        """Hash and store one capture, chained to the previous capture by the
        same collector of the same target. The chain is what makes a leak that
        appeared for one crawl and vanished on the next provable rather than
        anecdotal.

        Chained per collector, not merely per target: with page-level snapshots
        (`<collector>:page:/contact`) a per-target chain would link /contact to
        whichever page happened to be written before it, and `changed` would
        then flip on every crawl regardless of whether that page moved.
        """
        blob = _canon_json(payload)
        sha = hashlib.sha256(blob.encode()).hexdigest()
        prev = self._one(
            "SELECT snapshot_id, sha256, payload FROM snapshots WHERE target_id=? "
            "AND collector=? ORDER BY observed_at DESC, rowid DESC LIMIT 1",
            (target_id, collector))
        diff = None
        if prev:
            # The stored hash covers the whole payload, because that is what was
            # collected and provenance must not be selective. `changed` is
            # computed on a stripped copy: clock skew differs on every single
            # visit, so hashing it would report every re-check as a change and
            # bury the one that matters.
            try:
                before = _stable(json.loads(prev["payload"] or "{}"))
            except json.JSONDecodeError:
                before = None
            diff = _canon_json({
                "changed": before != _stable(payload),
                "prev": prev["snapshot_id"]})
        sid = self._id("snap")
        self.conn.execute(
            "INSERT INTO snapshots (snapshot_id, target_id, observed_at, collector, "
            "sha256, payload, raw_path, previous_snapshot_id, diff_summary) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (sid, target_id, observed_at or utcnow(), collector, sha, blob, raw_path,
             prev["snapshot_id"] if prev else None, diff),
        )
        self.conn.commit()
        return sid

    def snapshot_payload(self, snapshot_id: str) -> dict:
        row = self._one("SELECT payload FROM snapshots WHERE snapshot_id=?", (snapshot_id,))
        return json.loads(row["payload"]) if row and row["payload"] else {}

    # Page-level snapshots are written with this marker in the collector name so
    # site-level queries can exclude them: a page record holds one page's hash
    # and counts, not the artifact payload callers like the clone guard expect.
    PAGE_COLLECTOR = ":page:"

    def latest_snapshot(self, target_id: str, include_pages: bool = False,
                        status: Optional[str] = "OK") -> Optional[sqlite3.Row]:
        """Most recent capture of a target.

        Successful captures only by default. A DOWN record's payload is an error
        string, so handing it to anything that reads artifacts — the clone
        guard's similarity, for one — silently compares a site against its own
        outage and concludes the two markets look nothing alike.
        """
        return self._one(
            "SELECT * FROM snapshots WHERE target_id=? "
            + ("" if include_pages else "AND collector NOT LIKE '%:page:%' ")
            + ("AND status=? " if status else "")
            + "ORDER BY observed_at DESC, rowid DESC LIMIT 1",
            (target_id, status) if status else (target_id,))

    def record_down(self, target_id: str, collector: str, note: str = "",
                    observed_at: Optional[str] = None) -> str:
        """Record that the site did not answer, and mark the target inactive.

        Stored as a snapshot like any other capture, so 'this market was dark on
        this date' carries the same provenance as 'this key was on this page' —
        it is evidence a successor hypothesis stands on, not a log line.
        """
        sid = self.insert_snapshot(target_id, {"online": False, "error": note},
                                   collector=collector, observed_at=observed_at)
        self.conn.execute("UPDATE snapshots SET status='DOWN' WHERE snapshot_id=?", (sid,))
        self.conn.execute("UPDATE targets SET active=0 WHERE target_id=?", (target_id,))
        self.conn.commit()
        return sid

    def down_windows(self) -> Dict[str, str]:
        """target_id -> earliest time the site was observed dark."""
        return {r["target_id"]: r["first_down"] for r in self._all(
            "SELECT target_id, MIN(observed_at) AS first_down FROM snapshots "
            "WHERE status='DOWN' GROUP BY target_id")}

    def page_snapshots(self, target_id: str) -> List[sqlite3.Row]:
        """Every page-level capture of a target, newest first."""
        return self._all(
            "SELECT * FROM snapshots WHERE target_id=? AND collector LIKE '%:page:%' "
            "ORDER BY observed_at DESC, rowid DESC", (target_id,))

    # --- entities ------------------------------------------------------------

    def upsert_entity(self, etype: str, value: str, raw_value: Optional[str] = None,
                      metadata: Optional[dict] = None,
                      observed_at: Optional[str] = None) -> Optional[str]:
        """Normalize, then dedup on (etype, normalized_value).

        Returns None when the value fails validation — the caller must treat
        that as "this artifact does not exist", never as a nameless node. No
        normalized value, no entity, no edge.
        """
        if etype not in ENTITY_TYPES:
            raise ValueError(f"unknown entity type: {etype}")
        norm = normalize(etype, value)
        if norm is None:
            self.rejected[(etype, str(value)[:120])] += 1
            return None
        key = norm.lower()
        eid = self._id("ent", f"{etype}|{key}")
        now = observed_at or utcnow()
        self.conn.execute(
            "INSERT INTO entities (entity_id, etype, normalized_value, raw_value, "
            "metadata, first_seen, last_seen) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(etype, normalized_value) DO UPDATE SET "
            "  last_seen=MAX(entities.last_seen, excluded.last_seen), "
            "  first_seen=MIN(entities.first_seen, excluded.first_seen), "
            "  raw_value=COALESCE(entities.raw_value, excluded.raw_value)",
            (eid, etype, key, raw_value or value, _canon_json(metadata or {}), now, now),
        )
        self.conn.commit()
        return eid

    def find_entity(self, etype: str, value: str) -> Optional[str]:
        norm = normalize(etype, value)
        if norm is None:
            return None
        row = self._one("SELECT entity_id FROM entities WHERE etype=? AND normalized_value=?",
                        (etype, norm.lower()))
        return row["entity_id"] if row else None

    def set_metadata(self, entity_id: str, **fields) -> None:
        """Enrichment writes here — notably ip_class, which is decided from
        RDAP/ASN evidence and must never be guessed at extraction time."""
        if "ip_class" in fields and fields["ip_class"] not in IP_CLASSES:
            raise ValueError(f"unknown ip_class: {fields['ip_class']}")
        row = self._one("SELECT metadata FROM entities WHERE entity_id=?", (entity_id,))
        md = json.loads(row["metadata"]) if row and row["metadata"] else {}
        md.update(fields)
        self.conn.execute("UPDATE entities SET metadata=? WHERE entity_id=?",
                          (_canon_json(md), entity_id))
        self.conn.commit()

    def metadata(self, entity_id: str) -> dict:
        row = self._one("SELECT metadata FROM entities WHERE entity_id=?", (entity_id,))
        return json.loads(row["metadata"]) if row and row["metadata"] else {}

    # --- observations, relationships, evidence -------------------------------

    def insert_observation(self, snapshot_id: str, entity_id: str, method: str,
                           section: Optional[str] = None, context: Optional[str] = None,
                           confidence: float = 0.7,
                           observed_at: Optional[str] = None) -> str:
        oid = self._id("obs")
        self.conn.execute(
            "INSERT INTO observations (observation_id, snapshot_id, entity_id, "
            "extraction_method, section, context, confidence, observed_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (oid, snapshot_id, entity_id, method, section, (context or "")[:4000],
             confidence, observed_at or utcnow()),
        )
        self.conn.commit()
        return oid

    def upsert_relationship(self, source_id: str, target_id: str, rtype: str,
                            source_label: Optional[str] = None,
                            weight: Optional[float] = None,
                            observed_at: Optional[str] = None) -> str:
        """first_seen never moves forward. Temporal precedence between two
        markets using one key is the clone guard's whole discriminator, so an
        edge's first sighting is load-bearing evidence, not bookkeeping."""
        if rtype not in RELATIONSHIP_TYPES:
            raise ValueError(f"unknown relationship type: {rtype}")
        rid = self._id("rel", f"{source_id}|{target_id}|{rtype}")
        now = observed_at or utcnow()
        self.conn.execute(
            "INSERT INTO relationships (rel_id, source_entity_id, target_entity_id, "
            "rtype, source_label, first_seen, last_seen, weight) VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(source_entity_id, target_entity_id, rtype) DO UPDATE SET "
            "  first_seen=MIN(relationships.first_seen, excluded.first_seen), "
            "  last_seen=MAX(relationships.last_seen, excluded.last_seen), "
            "  weight=COALESCE(excluded.weight, relationships.weight)",
            (rid, source_id, target_id, rtype, source_label, now, now, weight),
        )
        self.conn.commit()
        return rid

    def add_evidence(self, relationship_id: str, observation_ids: List[str],
                     note: Optional[str] = None) -> str:
        eid = self._id("ev")
        self.conn.execute(
            "INSERT INTO evidence (evidence_id, relationship_id, observation_ids, note) "
            "VALUES (?,?,?,?)",
            (eid, relationship_id, _canon_json(list(observation_ids)), note),
        )
        self.conn.commit()
        return eid

    def add_finding(self, ftype: str, description: str, severity: str = "MEDIUM",
                    confidence: float = 0.5,
                    evidence_ids: Optional[List[str]] = None) -> str:
        """Deterministic id on (ftype, description): re-running an investigation
        refreshes a finding instead of stacking duplicates of it."""
        fid = self._id("find", f"{ftype}|{description}")
        now = utcnow()
        self.conn.execute(
            "INSERT INTO findings (finding_id, ftype, description, severity, confidence, "
            "evidence_ids, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(finding_id) DO UPDATE SET confidence=excluded.confidence, "
            "severity=excluded.severity, updated_at=excluded.updated_at",
            (fid, ftype, description, severity, confidence,
             _canon_json(evidence_ids or []), now, now),
        )
        self.conn.commit()
        return fid

    def findings(self, ftype: Optional[str] = None) -> List[sqlite3.Row]:
        if ftype:
            return self._all("SELECT * FROM findings WHERE ftype=? ORDER BY confidence DESC",
                             (ftype,))
        return self._all("SELECT * FROM findings ORDER BY confidence DESC")

    # --- provenance ----------------------------------------------------------

    def provenance(self, rel_id: str) -> List[dict]:
        """Walk a relationship back to the hashed snapshots supporting it. This
        is the query that makes a dossier defensible."""
        out = []
        for ev in self._all("SELECT * FROM evidence WHERE relationship_id=?", (rel_id,)):
            for oid in json.loads(ev["observation_ids"]):
                row = self._one(
                    "SELECT o.observation_id, o.extraction_method, o.section, o.context, "
                    "       o.observed_at, s.sha256, s.snapshot_id, t.url "
                    "FROM observations o "
                    "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
                    "JOIN targets t ON t.target_id = s.target_id "
                    "WHERE o.observation_id=?", (oid,))
                if row:
                    out.append(dict(row))
        return out

    def entities_sharing(self, etype: str) -> List[dict]:
        """Entities of one type observed on two or more distinct targets — the
        raw material of cross-market correlation."""
        rows = self._all(
            "SELECT e.entity_id, e.etype, e.normalized_value, "
            "       COUNT(DISTINCT s.target_id) AS n, "
            "       GROUP_CONCAT(DISTINCT t.url) AS targets "
            "FROM entities e "
            "JOIN observations o ON o.entity_id = e.entity_id "
            "JOIN snapshots s ON s.snapshot_id = o.snapshot_id "
            "JOIN targets t ON t.target_id = s.target_id "
            "WHERE e.etype=? GROUP BY e.entity_id HAVING n >= 2", (etype,))
        return [dict(r) | {"targets": sorted((r["targets"] or "").split(","))} for r in rows]

    def to_networkx(self):
        """Export for pyvis/networkx rendering. Both are already installed."""
        import networkx as nx
        g = nx.DiGraph()
        for e in self._all("SELECT * FROM entities"):
            g.add_node(e["entity_id"], etype=e["etype"], value=e["normalized_value"],
                       first_seen=e["first_seen"])
        for r in self._all("SELECT * FROM relationships WHERE status='ACTIVE'"):
            g.add_edge(r["source_entity_id"], r["target_entity_id"], rtype=r["rtype"],
                       first_seen=r["first_seen"], weight=r["weight"] or 1.0)
        return g


# --- adapter -----------------------------------------------------------------

def ingest(result: Any, store: EvidenceStore) -> List[str]:
    """Adapt a ModuleResult (or a saved ModuleResult.to_dict()) into evidence.

    Every existing module becomes an evidence producer by routing its output
    here — no module rewrite, only routing. Each SourceResult becomes one
    snapshot, so per-source provenance survives into the store.

    Returns the snapshot ids written.
    """
    data = result.to_dict() if hasattr(result, "to_dict") else result
    target_url = data.get("target") or ""
    if not target_url:
        return []

    # A module run against an IP or an email is enrichment about that thing, not
    # the discovery of a marketplace. Routing it through the market path below
    # would mint a MARKET entity for an address and put a fake storefront in
    # every correlation.
    ttype = (data.get("target_type") or "").lower()
    if ttype in _ENRICHERS:
        tid = store.upsert_target(target_url)
        sid = _ingest_enrichment(store, target_url, ttype, data.get("summary") or {},
                                 data.get("module") or ttype,
                                 _result_time(data) or utcnow(), tid)
        return [sid] if sid else []

    target_id = store.upsert_target(target_url)
    market_id = store.upsert_entity("MARKET", target_url)
    onion = store.upsert_entity("ONION_ADDRESS", target_url)

    snapshot_ids = []
    for name, src in (data.get("sources") or {}).items():
        if not src.get("success"):
            # A failed fetch is not an observation OF the site — but a site that
            # answered nothing when we asked is a fact about the site, and it is
            # the fact the successor logic turns on: without it, "A stopped and
            # B started" is indistinguishable from "we looked at A first".
            if name in _SITE_COLLECTORS and _site_was_down(src.get("error")):
                snapshot_ids.append(store.record_down(
                    target_id, collector=name, note=str(src.get("error") or "")[:300],
                    observed_at=src.get("timestamp")))
            continue
        payload = src.get("data") or {}
        observed_at = src.get("timestamp") or utcnow()
        sid = store.insert_snapshot(target_id, payload, collector=name,
                                    observed_at=observed_at)
        snapshot_ids.append(sid)

        if onion and market_id:
            rel = store.upsert_relationship(market_id, onion, "HAS_ADDRESS",
                                            source_label=name, observed_at=observed_at)
            store.add_evidence(rel, [], note=f"target address, seen by {name}")

        # Where on the page each artifact was seen, when the collector recorded
        # it: a contact-block address is better evidence than one in a comment.
        seen_at = payload.get("artifact_evidence") or {}
        # One snapshot per crawled page, so an observation resolves to the hash
        # of the page it was actually read off rather than to the whole visit.
        page_snaps = _ingest_pages(store, target_id, payload, name, observed_at)

        for key, (etype, rtype) in ARTIFACT_MAP.items():
            # An index returns what ranked beside the target, not what the target
            # links to. Everything else in its payload still counts: a paste that
            # names this market and an email is real evidence about it.
            index_hit = key == "onion_addresses_found" and name in _INDEX_SOURCES
            for raw in payload.get(key) or []:
                # The target's own address is already HAS_ADDRESS; re-adding it as
                # a link would make every market cite itself as an associate.
                if etype == "ONION_ADDRESS" and \
                        normalize(etype, str(raw)) == normalize(etype, target_url):
                    continue
                where = seen_at.get(raw) or {}
                _link(store, page_snaps.get(where.get("page"), sid), market_id, etype,
                      "DISCOVERED_VIA" if index_hit else rtype, str(raw), name,
                      section=where.get("section") or key,
                      # An index co-ranking is provenance, not a claim about the
                      # site, so it is recorded at a confidence that cannot on
                      # its own carry an edge into a candidate.
                      confidence=0.3 if index_hit else 0.7,
                      context=where.get("context"), observed_at=observed_at)

        # The server's own build signature. Declared in ENTITY_TYPES but never
        # written until now, so a self-hosted market's strongest operator tell
        # reached the dossier and stopped there, invisible to correlation.
        signature = fingerprint_signature(payload.get("server_fingerprint") or {})
        if signature:
            _link(store, sid, market_id, "HTTP_FINGERPRINT", "HAS_FINGERPRINT",
                  signature, name, section="server_fingerprint",
                  confidence=0.8, observed_at=observed_at)

        # Prefer the true fingerprint; fall back to the collector's key_id, which
        # normalize keeps in a separate PGP:KEYID: namespace precisely so a weak
        # id never merges into a fingerprint's node.
        for key in payload.get("pgp_keys") or []:
            value = key.get("armored") or key.get("fingerprint") or key.get("key_id")
            if not value:
                continue
            # Role decides the edge type, and the edge type is what stops a
            # copied key reading like control of a key: SIGNS_WITH means the page
            # carried a signature this key issued, USES_PGP only that it showed
            # the block. Cloning reproduces the second and not the first.
            role = key.get("role") or "displayed"
            key_id = _link(store, sid, market_id, "PGP_KEY",
                           "SIGNS_WITH" if role == "signing" else "USES_PGP",
                           str(value), name, section=f"pgp_keys:{role}",
                           confidence=0.85 if role == "signing" else 0.7,
                           observed_at=observed_at)
            if key_id:
                store.set_metadata(key_id, role=role)
            # occam: 20 certifiers per key. A keyring-signed key can carry
            # hundreds, and past the first few they are web-of-trust background
            # rather than evidence about this operator. Raise it if a real case
            # turns on a certifier deep in the list.
            for certifier in (key.get("certifiers") or [])[:20]:
                cert_id = store.upsert_entity("PGP_KEY", str(certifier),
                                              observed_at=observed_at)
                if not (cert_id and key_id) or cert_id == key_id:
                    continue
                obs = store.insert_observation(
                    sid, cert_id, method=f"{name}:pgp_certification", section="pgp_keys",
                    context=f"certified {value}", confidence=0.9, observed_at=observed_at)
                rel = store.upsert_relationship(cert_id, key_id, "SIGNED_BY",
                                                source_label=name, observed_at=observed_at)
                store.add_evidence(
                    rel, [obs], note="third-party certification inside the published key")

        for match in ((payload.get("favicon") or {}).get("shodan_matches") or []):
            ip_id = _link(store, sid, market_id, "IP", "CANDIDATE_IP", str(match.get("ip") or ""),
                          name, section="favicon", confidence=0.5, observed_at=observed_at)
            if ip_id and match.get("org"):
                # The owner is evidence about the host, so it belongs on the IP
                # entity too — correlate reads org/ip_class off metadata when it
                # builds an IP candidate.
                store.set_metadata(ip_id, org=str(match["org"]), isp=match.get("isp"),
                                   ip_class=classify_ip(str(match["org"]), match.get("isp")))
                org = store.upsert_entity("HOSTING_PROVIDER", str(match["org"]))
                if org:
                    store.upsert_relationship(ip_id, org, "OWNED_BY", source_label=name,
                                              observed_at=observed_at)

        for mc in payload.get("misconfigurations") or []:
            for ip in mc.get("leaked_ips") or []:
                _link(store, sid, market_id, "IP", "HOSTED_ON", str(ip), name,
                      section=f"misconfig{mc.get('path', '')}", confidence=0.9,
                      observed_at=observed_at)

        # The onion visit pivots its artifacts through the ip/email modules and
        # carries each summary back here. Those are already-paid-for enrichment
        # lookups, so they become evidence on the artifact's own entity — the
        # pivot's whole point is that the market and the enrichment end up on one
        # graph instead of in two unrelated reports.
        for pivot in (payload.get("results") or []) if name == "operator_pivot" else []:
            sub = _ingest_enrichment(store, str(pivot.get("target") or ""),
                                     str(pivot.get("type") or "").lower(),
                                     pivot.get("summary") or {},
                                     f"{name}:pivot", observed_at, target_id)
            if sub:
                snapshot_ids.append(sub)

    return snapshot_ids


def _ingest_pages(store: EvidenceStore, target_id: str, payload: dict, collector: str,
                  observed_at: str) -> Dict[str, str]:
    """One snapshot per crawled page. Returns {path: snapshot_id}.

    Page-level lineage is what makes a claim reproducible at the granularity it
    was made: "this key was on /contact at this hash" survives the operator
    editing the landing page, while a single site-level snapshot only shows that
    *something* changed. Each page also chains to its own previous capture (see
    insert_snapshot), so a page-level diff is a real before/after.
    """
    out: Dict[str, str] = {}
    for page in payload.get("pages") or []:
        path = str(page.get("path") or page.get("url") or "")
        if not path or path in out:
            continue
        out[path] = store.insert_snapshot(
            target_id, page, collector=f"{collector}{EvidenceStore.PAGE_COLLECTOR}{path}",
            observed_at=observed_at)
    return out


def _result_time(data: dict) -> Optional[str]:
    """Earliest source timestamp — provenance for a standalone module run, which
    has no page capture of its own to date it by."""
    stamps = [s.get("timestamp") for s in (data.get("sources") or {}).values()
              if s.get("success") and s.get("timestamp")]
    return min(stamps) if stamps else None


def enrich_ip(store: EvidenceStore, snapshot_id: str, ip_id: str, summary: dict,
              collector: str, observed_at: Optional[str] = None) -> None:
    """Attach an ip module summary to an IP already in the store.

    RDAP/ASN answers arrive as attributes of a host, not as new artifacts, so
    they land two ways: the operational verdict (ip_class, org, abuse score) as
    metadata correlate reads when ranking, and the network itself as real ASN /
    provider nodes, because those are shared — two markets on one AS is a
    convergence the graph should be able to show.
    """
    org, asn = summary.get("org"), summary.get("asn")
    store.set_metadata(
        ip_id,
        **{k: v for k, v in (("org", org), ("asn", asn),
                             ("hostname", summary.get("hostname")),
                             ("country", summary.get("country")),
                             ("abuse_score", summary.get("abuse_score"))) if v},
        ip_class=classify_ip(org or "", summary.get("isp"), summary),
    )

    for etype, rtype, value in (("ASN", "BELONGS_TO_ASN", asn),
                                ("HOSTING_PROVIDER", "OWNED_BY", org)):
        if not value:
            continue
        node = store.upsert_entity(etype, str(value), observed_at=observed_at)
        if not node:
            continue                        # not an AS number, just a company name
        obs = store.insert_observation(snapshot_id, node, method=f"{collector}:enrichment",
                                       section="enrichment", context=str(value),
                                       confidence=0.9, observed_at=observed_at)
        rel = store.upsert_relationship(ip_id, node, rtype, source_label=collector,
                                        observed_at=observed_at)
        store.add_evidence(rel, [obs], note=f"{collector} enrichment for this host")

    # A hostname is a real clearnet name for the host, and the pivot most worth
    # having: passive DNS on it outlives the IP lease.
    if summary.get("hostname"):
        _link(store, snapshot_id, ip_id, "DOMAIN", "RESOLVES_TO",
              str(summary["hostname"]), collector, section="enrichment",
              confidence=0.8, observed_at=observed_at)


def enrich_email(store: EvidenceStore, snapshot_id: str, email_id: str, summary: dict,
                 collector: str, observed_at: Optional[str] = None) -> None:
    """Attach an email module summary — keyserver keys and discovered handles.

    The keyserver edge is the valuable one: it ties an address to a fingerprint
    independently of the market page, so a key found on two markets and a key
    published under an operator's address are the same node rather than two
    coincidences.
    """
    for fpr in summary.get("pgp_fingerprints") or []:
        _link(store, snapshot_id, email_id, "PGP_KEY", "ASSOCIATED_WITH", str(fpr),
              collector, section="keyserver", confidence=0.85, observed_at=observed_at)

    for user in summary.get("github_usernames") or []:
        _link(store, snapshot_id, email_id, "USERNAME", "USES_USERNAME", str(user),
              collector, section="github", confidence=0.75, observed_at=observed_at)


def enrich_bitcoin(store: EvidenceStore, snapshot_id: str, addr_id: str, summary: dict,
                   collector: str, observed_at: Optional[str] = None) -> None:
    """Attach a bitcoin module summary to a BTC address already in the store.

    Only co-spend addresses become cluster edges. Under common-input-ownership,
    signing two addresses into one transaction's inputs proves the same party
    held both keys — that is a control relation. Being *paid* by an address
    proves only a transaction happened, so counterparties stay metadata: merging
    them would put every customer of a market inside the operator's wallet and
    then hand correlation a cluster shared by every market with a customer in
    common. Components are assembled at correlation time, so a cluster grows as
    evidence arrives instead of being frozen at first sight.

    occam: no exchange tagging or change-address heuristics — both need a
    labelled dataset this tool does not ship. The cluster therefore claims "one
    wallet", never "not an exchange"; correlate carries that caveat.
    """
    store.set_metadata(
        addr_id,
        **{k: v for k, v in (("balance", summary.get("balance")),
                             ("tx_count", summary.get("tx_count")),
                             ("first_tx", summary.get("first_seen")),
                             ("last_tx", summary.get("last_seen")),
                             ("reported_scam", summary.get("reported_scam"))) if v})

    row = store._one("SELECT etype FROM entities WHERE entity_id=?", (addr_id,))
    etype = row["etype"] if row else "BTC_ADDRESS"
    for peer in (summary.get("cospend_addresses") or [])[:20]:
        peer_id = store.upsert_entity(etype, str(peer), observed_at=observed_at)
        if not peer_id or peer_id == addr_id:
            continue
        obs = store.insert_observation(
            snapshot_id, peer_id, method=f"{collector}:cospend", section="blockchain",
            context=f"co-spent with {summary.get('address') or ''} in one transaction",
            confidence=0.85, observed_at=observed_at)
        rel = store.upsert_relationship(addr_id, peer_id, "PART_OF_CLUSTER",
                                        source_label=collector, observed_at=observed_at)
        store.add_evidence(rel, [obs], note="common-input-ownership heuristic")


# Which pivot/module target types have an enrichment router, and the entity each
# one anchors to. Adding a module here is what makes its output evidence.
_ENRICHERS = {
    "ip":       ("IP", enrich_ip),
    "email":    ("EMAIL", enrich_email),
    "bitcoin":  ("BTC_ADDRESS", enrich_bitcoin),
    "ethereum": ("ETH_ADDRESS", enrich_bitcoin),
}


def _ingest_enrichment(store: EvidenceStore, target: str, ttype: str, summary: dict,
                       collector: str, observed_at: str, target_id: str) -> Optional[str]:
    """Route one enrichment summary onto its subject entity. Returns snapshot id.

    The subject is upserted rather than required to exist: enrichment may arrive
    before the market that mentions the address, and the store dedupes either
    way, so ordering never decides whether the evidence lands.
    """
    entry = _ENRICHERS.get(ttype)
    if not entry or not summary:
        return None
    etype, enricher = entry
    subject = store.upsert_entity(etype, target, observed_at=observed_at)
    if subject is None:
        return None
    sid = store.insert_snapshot(target_id, summary, collector=collector,
                                observed_at=observed_at)
    store.insert_observation(sid, subject, method=f"{collector}:enrichment",
                             section="enrichment", context=target,
                             confidence=0.9, observed_at=observed_at)
    enricher(store, sid, subject, summary, collector, observed_at)
    return sid


def _link(store: EvidenceStore, snapshot_id: str, source_entity: Optional[str],
          etype: str, rtype: str, raw: str, collector: str, section: str,
          confidence: float = 0.7, context: Optional[str] = None,
          observed_at: Optional[str] = None) -> Optional[str]:
    """entity -> observation -> relationship -> evidence, in one hop.

    Everything downstream depends on this chain existing for every artifact, so
    it lives in one place rather than being re-spelled per artifact type.
    """
    entity_id = store.upsert_entity(etype, raw, observed_at=observed_at)
    if entity_id is None:
        return None                        # failed normalization: not an artifact
    obs = store.insert_observation(snapshot_id, entity_id, method=f"{collector}:{section}",
                                   section=section, context=context or raw,
                                   confidence=confidence, observed_at=observed_at)
    if source_entity and source_entity != entity_id:
        rel = store.upsert_relationship(source_entity, entity_id, rtype,
                                        source_label=collector, observed_at=observed_at)
        store.add_evidence(rel, [obs])
    return entity_id


# --- clone guard -------------------------------------------------------------

def structural_similarity(a: dict, b: dict) -> Optional[float]:
    """Template likeness of two captures from their per-page DOM simhashes.

    Compares each page of A against its best match in B, then averages: a clone
    copies the whole site, so its pages match one-to-one even when paths differ,
    while a site that merely shares one framework page does not.

    None when either capture predates per-page fingerprints — the caller then
    falls back to the artifact bag rather than reading a missing field as 0.0
    and quietly declaring two identical sites dissimilar.
    """
    def hashes(d: dict) -> list:
        return [p["dom_simhash"] for p in (d.get("pages") or []) if p.get("dom_simhash")]

    ha, hb = hashes(a), hashes(b)
    if not ha or not hb:
        return None
    best = [max(simhash_similarity(x, y) for y in hb) for x in ha]
    return round(sum(best) / len(best), 4)


def page_similarity(a: dict, b: dict) -> float:
    """How alike two captures look, from the payloads actually collected.

    Structure first, artifacts second. Two markets sharing a key look identical
    to the artifact bag whether one copied the other or the same operator built
    both; the DOM fingerprint is what separates "copied this site" from "reused
    this key", and it survives the copycat rewriting every word on the page.
    The artifact bag remains the fallback for captures collected before
    fingerprints existed.
    """
    def bag(d: dict) -> set:
        out = set()
        for key in ARTIFACT_MAP:
            out |= {f"{key}:{v}" for v in (d.get(key) or [])}
        for k in (d.get("pgp_keys") or []):
            out.add(f"pgp:{k.get('key_id') or k.get('fingerprint')}")
        return out

    sa, sb = bag(a), bag(b)
    jaccard = len(sa & sb) / len(sa | sb) if (sa or sb) else 0.0
    title_match = bool(a.get("title")) and a.get("title") == b.get("title")
    artifact_score = min(1.0, jaccard + (0.2 if title_match else 0.0))

    structural = structural_similarity(a, b)
    if structural is None:
        return artifact_score
    # Weighted toward structure without ignoring artifacts: a rebuilt successor
    # keeps the keys and drops the template, a clone does the reverse, and the
    # guard has to be able to see both.
    return round(min(1.0, 0.65 * structural + 0.35 * artifact_score), 4)


def detect_clones(store: EvidenceStore) -> List[dict]:
    """Turn shared PGP keys into findings that CONSTRAIN attribution.

    A shared key is never allowed to mean "same operator" on its own: markets
    copy each other's published keys, and a scraper that merges on key reuse
    will confidently attribute a clone's traffic to its victim. So each shared
    key is classified first:

      earlier market + high page similarity  -> CLONE_SUSPECT
          the later site copied the key along with everything else; the
          apparent operator link is an artifact of copying, not shared control.

      earlier market + low page similarity   -> SUCCESSOR_CANDIDATE
          a distinct site reusing an old key looks like the same operator
          rebuilding after a takedown.

    Both land as findings, so correlation must reckon with the contradiction
    before it can promote a shared key into an operator claim.

    Role is the second discriminator. A market that merely DISPLAYS a key proves
    nothing a copycat could not also do; one that carried a signature the key
    issued (SIGNS_WITH) demonstrated control of the secret half. So a signing
    later market has to look almost pixel-identical before it is called a clone.

    occam: a signature is control at *some* time, not necessarily now — the
    collector does not check the signature's own timestamp against the capture,
    so a copycat republishing an old signed announcement still reads as signing.
    Compare the signature creation time to the crawl if that shows up in a case.
    """
    findings = []
    for shared in store.entities_sharing("PGP_KEY"):
        rows = store._all(
            "SELECT r.rel_id, r.first_seen, r.rtype, e.normalized_value AS market "
            "FROM relationships r JOIN entities e ON e.entity_id = r.source_entity_id "
            "WHERE r.target_entity_id=? AND r.rtype IN ('USES_PGP','SIGNS_WITH') "
            "ORDER BY r.first_seen", (shared["entity_id"],))
        if len(rows) < 2:
            continue
        first = rows[0]
        for later in rows[1:]:
            if later["first_seen"] <= first["first_seen"]:
                continue                   # no precedence: cannot tell who copied whom
            sim = _similarity_between(store, first["market"], later["market"])
            clone = sim >= (0.95 if later["rtype"] == "SIGNS_WITH" else 0.85)
            findings.append(_record_clone(store, first, later, shared, sim, clone))
    return findings


def _similarity_between(store: EvidenceStore, market_a: str, market_b: str) -> float:
    payloads = []
    for url in (market_a, market_b):
        row = store._one("SELECT target_id FROM targets WHERE url=?", (url,))
        snap = store.latest_snapshot(row["target_id"]) if row else None
        payloads.append(store.snapshot_payload(snap["snapshot_id"]) if snap else {})
    return page_similarity(*payloads)


def _record_clone(store: EvidenceStore, first, later, shared: dict,
                  sim: float, clone: bool) -> dict:
    ftype = "CLONE_SUSPECT" if clone else "SUCCESSOR_CANDIDATE"
    key = shared["normalized_value"]
    description = (
        f"{later['market']} displays {key} first seen on {first['market']} "
        f"({first['first_seen']}); page similarity {sim:.2f}"
        if clone else
        f"{later['market']} reuses {key} first seen on {first['market']} "
        f"({first['first_seen']}) on an otherwise dissimilar site (similarity {sim:.2f})"
    )
    confidence = round(min(0.95, sim), 2) if clone else 0.6
    fid = store.add_finding(ftype, description, severity="HIGH", confidence=confidence)
    return {
        "finding_id": fid, "ftype": ftype, "confidence": confidence,
        "shared_key": key, "earlier": first["market"], "later": later["market"],
        "similarity": round(sim, 3), "description": description,
    }
