"""cybertrace.stylometry: pure-algorithm tests need no corpus; one sanity
check against the real Evolution download mirrors test_integrations.py's own
@pytest.mark.skipif convention."""
import pytest

from cybertrace.integrations import evolution
from cybertrace.stylometry import MIN_PROFILE_CHARS, char_ngrams, clean_text, profile, similarity


def test_clean_text_strips_nested_quoteboxes_not_the_reply():
    html = ('<div class="quotebox"><cite>a wrote:</cite><blockquote><div>'
            '<div class="quotebox"><cite>b wrote:</cite><blockquote><div><p>inner</p>'
            '</div></blockquote></div><p>outer-quoted</p></div></blockquote></div>'
            '<p>my real reply</p>')
    cleaned = clean_text(html)
    assert "inner" not in cleaned
    assert "outer-quoted" not in cleaned
    assert "my real reply" in cleaned


def test_clean_text_strips_pgp_armor_not_surrounding_prose():
    html = ('<p>see my key</p>-----BEGIN PGP SIGNATURE-----\n'
            'iQEcBAEBAgAGBQJS1LNA\n-----END PGP SIGNATURE-----<p>bye</p>')
    cleaned = clean_text(html)
    assert "iqecbaebagagbqjs1lna" not in cleaned
    assert "see my key" in cleaned and "bye" in cleaned


def test_clean_text_unescapes_entities_and_lowercases():
    assert clean_text("<p>Don&#039;t &quot;quote&quot; ME</p>") == "don't \"quote\" me"


def test_clean_text_empty_input():
    assert clean_text("") == ""
    assert clean_text(None) == ""


def test_char_ngrams_shorter_than_n_is_empty():
    assert char_ngrams("ab", n=4) == {}


def test_similarity_identical_text_is_one():
    text = "the quick brown fox jumps over the lazy dog " * 10
    assert similarity(profile(text), profile(text)) == 1.0


def test_similarity_disjoint_vocabulary_is_low():
    a = profile("the quick brown fox jumps over the lazy dog " * 10)
    b = profile("xyzzy plugh qwerty zxcvbn mnbvcx wertyu " * 10)
    assert similarity(a, b) < 0.2


def test_similarity_empty_profile_is_zero_not_an_error():
    assert similarity({}, profile("some real text here")) == 0.0
    assert similarity({}, {}) == 0.0


@pytest.mark.skipif(not evolution.available(), reason="Evolution dataset not downloaded locally")
def test_real_corpus_has_at_least_one_multi_account_identity_with_enough_text():
    from collections import defaultdict

    texts = defaultdict(list)
    groups = defaultdict(set)
    for row in evolution.iter_identity_nodes():
        mid = row.get("match_id")
        for col in ("uid", "secondary_uid", "tertiary_uid"):
            if row.get(col):
                groups[mid].add(row[col])
    multi = {mid: uids for mid, uids in groups.items() if len(uids) >= 2}
    assert multi, "expected at least one multi-uid identity in network/nodes.tsv"

    wanted = {u for uids in multi.values() for u in uids}
    for row in evolution.iter_forum_posts():
        if row["uid"] in wanted:
            cleaned = clean_text(row.get("text") or "")
            if cleaned:
                texts[row["uid"]].append(cleaned)
            if sum(len(v) for v in texts.values()) > 200000:
                break  # bounded scan -- this is a sanity check, not the real eval

    profiled = {uid: " ".join(t) for uid, t in texts.items() if len(" ".join(t)) >= MIN_PROFILE_CHARS}
    assert profiled, "expected at least one real account to clear MIN_PROFILE_CHARS in a bounded scan"
