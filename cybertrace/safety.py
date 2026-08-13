"""Content-safety gate: the categories this tool must never fetch or persist.

CyberTrace crawls live onion services, so a scrape can land on material that is
illegal to possess regardless of intent. Three gates, each in the one function
every caller already routes through:

    query   cli.search()           -> refuse to investigate the target at all
    URL     BaseModule._session_for -> refuse the request before it is sent
    content BaseModule.fetch / _fetch_full -> drop the body before anything reads it

Scope is deliberately narrow: CSAM and gore/snuff only. It is NOT a general
adult-content or profanity filter, and that restraint is the design. Attribution
runs on operator handles, market names and page text; a broad blocklist (the
kind that drops any value containing "escort", "admin" or "master") would delete
the evidence this tool exists to collect, while doing nothing about the material
that is actually a liability. Over-blocking here is not a safe default — it is a
different failure with the same shrug.

Nothing prohibited is ever logged. Events record a SHA-256 prefix of the subject
so two hits can be correlated, and nothing else.
"""

from __future__ import annotations

import hashlib
import logging
import re

logger = logging.getLogger(__name__)


class BlockedContent(Exception):
    """A URL was refused by the safety gate. Raised where the request would be
    sent, so every fetch helper's existing `except Exception` turns it into the
    same no-data outcome as an unreachable host."""


# Word-boundary matched against free text. Substring matching (VoidAccess does
# this) fires on "torpedo", "childhood" and "scoregore"; in an attribution tool
# a false drop silently loses evidence, so the boundaries are load-bearing.
# Multi-word entries tolerate any run of non-letters between words, because
# scraped HTML separates them with tags, newlines and entities.
_TEXT_TERMS = (
    # CSAM
    r"child (?:porn\w*|sex\w*|abuse material|model)", r"childporn\w*",
    r"cp porn", r"csam", r"pedo\w*", r"paedo\w*",
    r"lolita", r"jailbait", r"preteen sex", r"minor sex", r"underage sex",
    r"hurtcore", r"daisy'?s destruction",
    # Gore / snuff
    r"snuff (?:film|porn|video)", r"murder (?:porn|video)",
    r"(?:execution|beheading|torture) video",
    r"best ?gore", r"live ?gore", r"watch ?people ?die", r"real ?snuff",
)

_TEXT_RE = re.compile(
    r"\b(?:%s)\b" % "|".join(t.replace(" ", r"[^a-z0-9]{0,4}") for t in _TEXT_TERMS),
    re.IGNORECASE,
)

# URLs concatenate words, so these match as plain substrings — no boundaries.
_URL_TERMS = (
    "pedo", "paedo", "loli", "jailbait", "childporn", "childsex",
    "hurtcore", "csam", "bestgore", "livegore", "watchpeopledie", "realsnuff",
)

# A v3 onion label is 56 random base32 chars, so it hits any 4-letter substring
# roughly once in 20k addresses. Strip the label before matching or the gate
# eventually refuses a legitimate market on a coincidence.
_ONION_LABEL = re.compile(r"[a-z2-7]{56}", re.IGNORECASE)


def _digest(subject: str) -> str:
    """Correlation handle for a blocked item. Never the item itself."""
    return hashlib.sha256(subject.encode("utf-8", "replace")).hexdigest()[:16]


def _log(event: str, subject: str) -> None:
    logger.warning("content_safety: %s (sha256:%s)", event, _digest(subject))


def is_blocked_query(query: str) -> bool:
    """True if the investigation target itself names prohibited material."""
    if not query or not _TEXT_RE.search(query):
        return False
    _log("query_blocked", query)
    return True


def is_blocked_url(url: str) -> bool:
    """True if the URL should never be requested."""
    if not url:
        return False
    stripped = _ONION_LABEL.sub("", url).lower()
    if not any(term in stripped for term in _URL_TERMS):
        return False
    _log("url_blocked", url)
    return True


def scrub(text: str, source: str = "") -> str:
    """Return `text`, or "" if it trips the content gate.

    All-or-nothing on purpose: prohibited material is not reliably separable
    from the rest of a page, and a partial redaction still persists whatever the
    pattern missed. The caller sees an empty body and extracts nothing.

    occam: the emptied page is indistinguishable from a blank one downstream.
    Thread a `content_blocked` flag into SourceResult.error if an analyst ever
    needs to tell "page had nothing" from "we refused to keep it".
    """
    if not text or not _TEXT_RE.search(text):
        return text
    _log(f"content_blocked{f' [{source}]' if source else ''}", text)
    return ""
