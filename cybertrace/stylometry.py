"""Stylometric similarity: character n-gram author profiles, cosine-compared.

Offline algorithm only — this module never touches EvidenceStore/correlate.py
and is not itself an attribution signal. It answers one question in isolation:
"how similar are two authors' n-gram profiles", nothing about what that
similarity is worth as evidence. See tools/eval_stylometry.py for the
measured precision/recall against external_data/evolution's own ground truth,
and correlate.py's CONTEXT_WEIGHT/NON_ATTRIBUTIVE_SIGNALS comments for how
every other signal in this codebase earns its weight from a real number, not
an assumption — this one is held to the same standard before it is wired
anywhere near a candidate score.

Method: character n-gram frequency profiles (Kešelj/Peng-style author
profiling) + cosine similarity. Chosen over normalize.dom_simhash's tag/class
shingling because that comparator measures template *structure*, not prose —
recalibrating it for authorship would just be a different job wearing the
same code. Chosen over a function-word/stopword feature vector because it
needs no curated word list and degrades gracefully on the short, informal,
typo-heavy text real forum posts turn out to be (median 181 raw chars per
post, measured against the real corpus — see MIN_PROFILE_CHARS below).
"""

from __future__ import annotations

import html as _html
import math
import re
from collections import Counter

# Real post.tsv rows nest reply quoting as
# <div class="quotebox"><cite>user wrote:</cite><blockquote>...</blockquote></div>,
# and quotes-of-quotes really do occur (measured on the real corpus) — a
# non-greedy regex up to the first </div> would cut off inside the nested
# quotebox and leave the *quoted* author's remaining words attached to the
# outer post, mixing two authors' prose into one profile. _strip_quoteboxes
# tracks div-open/div-close depth instead, so nesting of any depth is removed
# as one unit.
_QUOTEBOX_OPEN = re.compile(r'<div\s+class="quotebox"[^>]*>', re.IGNORECASE)
_DIV_TAG = re.compile(r'<(/?)div\b[^>]*>', re.IGNORECASE)

# Forum posts include full PGP-signed messages and signature blocks (measured
# on the real corpus) — base64 noise, not prose, and would dominate an n-gram
# profile if left in. Same block shape integrations/evolution.py's
# _ARMOR_BLOCK matches, used here to remove rather than parse.
_ARMOR_BLOCK = re.compile(r'-----BEGIN PGP [A-Z ]+?-----.*?-----END PGP [A-Z ]+?-----', re.DOTALL)
_TAG = re.compile(r'<[^>]+>')
_WS = re.compile(r'\s+')

# Real median post length is 181 raw HTML chars (mean 403, 20K-row sample) --
# cleaned prose per post is shorter still, so one profile is many posts
# aggregated. 300 cleaned chars is roughly what dedupe'd posts from a
# lightly-active account provide; below it a profile is mostly sparse zeros
# and cosine similarity becomes noise, not signal.
MIN_PROFILE_CHARS = 300


def _strip_quoteboxes(text: str) -> str:
    out, pos = [], 0
    while True:
        m = _QUOTEBOX_OPEN.search(text, pos)
        if not m:
            out.append(text[pos:])
            break
        out.append(text[pos:m.start()])
        depth, i = 1, m.end()
        for tag in _DIV_TAG.finditer(text, m.end()):
            depth += -1 if tag.group(1) else 1
            if depth == 0:
                i = tag.end()
                break
        else:
            i = len(text)  # unterminated quotebox (truncated row) -- drop the rest
        pos = i
    return "".join(out)


def clean_text(raw_html: str) -> str:
    """Free-text prose only: no markup, no quoted other-author text, no
    PGP-armor noise, entities unescaped, whitespace collapsed, lowercased."""
    if not raw_html:
        return ""
    text = _strip_quoteboxes(raw_html)
    text = _ARMOR_BLOCK.sub(" ", text)
    text = _TAG.sub(" ", text)
    text = _html.unescape(text)
    return _WS.sub(" ", text).strip().lower()


def char_ngrams(text: str, n: int = 4) -> Counter:
    if len(text) < n:
        return Counter()
    return Counter(text[i:i + n] for i in range(len(text) - n + 1))


def profile(text: str, n: int = 4, top_k: int = 300) -> Counter:
    """The top_k most frequent n-grams and their counts -- an author
    profile, not a full-text fingerprint (Kešelj/Peng "common n-gram"
    method: the most frequent n-grams are dominated by function words and
    common morphology, which carry style; the long tail is mostly topic
    vocabulary, which doesn't)."""
    return Counter(dict(char_ngrams(text, n).most_common(top_k)))


def similarity(a: Counter, b: Counter) -> float:
    """Cosine similarity between two n-gram profiles, 0..1. 0.0 if either is
    empty (never divide into a false 0.0 vs. a genuine no-overlap profile --
    both read the same, and callers already gate on MIN_PROFILE_CHARS before
    trusting a profile at all)."""
    if not a or not b:
        return 0.0
    shared = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in shared)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if not norm_a or not norm_b:
        return 0.0
    return round(dot / (norm_a * norm_b), 4)


def demo() -> None:
    """occam: smallest runnable check for the cleaning/profiling/similarity
    chain — the corpus-scale precision/recall measurement itself lives in
    tools/eval_stylometry.py and needs the real 401MB download, not a
    pytest-speed self-check."""
    nested = ('<div class="quotebox"><cite>a wrote:</cite><blockquote><div>'
              '<div class="quotebox"><cite>b wrote:</cite><blockquote><div><p>inner</p>'
              '</div></blockquote></div><p>outer-quoted</p></div></blockquote></div>'
              '<p>my real reply &amp; more</p>')
    cleaned = clean_text(nested)
    assert "inner" not in cleaned and "outer-quoted" not in cleaned, cleaned
    assert "my real reply & more" in cleaned, cleaned

    armored = '<p>see my key</p>-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----<p>bye</p>'
    cleaned2 = clean_text(armored)
    assert "aaaa" not in cleaned2 and "see my key" in cleaned2 and "bye" in cleaned2, cleaned2

    same = "the quick brown fox jumps over the lazy dog " * 20
    other = "xyzzy plugh qwerty asdf zxcv mnbq wert yuio " * 20
    p1, p2, p3 = profile(same), profile(same), profile(other)
    assert similarity(p1, p2) == 1.0
    assert similarity(p1, p3) < 0.2, similarity(p1, p3)
    assert similarity(Counter(), p1) == 0.0
    print("stylometry.demo() OK")


if __name__ == "__main__":
    demo()
