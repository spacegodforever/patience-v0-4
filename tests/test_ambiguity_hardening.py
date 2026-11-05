"""Evasion hardening for the language ambiguity analyzer (v2) + labeled-corpus metrics."""
import os
import sys

import pytest

from dev_governance import ambiguity
from dev_governance.ambiguity import normalize

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import eval_ambiguity  # noqa: E402

DROP = {"table": "payments", "rollback_plan": "restore snapshot snap-42 with pg_restore",
        "backup": {"snapshot_id": "snap-42"}, "blast_radius": {"rows": 5000, "resources": 1}}
MERGE = {"repo": "a/b", "pr_number": 3}
ZW = "\u200b"


@pytest.mark.parametrize("raw,want", [
    ("d3l3t3 4ll r0ws", "delete all rows"),                 # leetspeak
    ("n|_|ke everything", "nuke everything"),               # multi-char leet
    ("d\u0435l\u0435te", "delete"),                         # Cyrillic homoglyphs
    ("\u03bfverride", "override"),                          # Greek homoglyph
    (f"de{ZW}le\u200cte", "delete"),                        # zero-width
    ("pu\u00adrge", "purge"),                               # soft hyphen
    ("D.R.O.P the table", "drop the table"),                # dotted
    ("W I P E   everything", "wipe everything"),            # spaced + whitespace
    ("p-u-r-g-e", "purge"),                                 # hyphenated letters
    ("\ufb01x it", "fix it"),                               # NFKC ligature
    ("ＤＲＯＰ", "drop"),                                    # fullwidth
    ("DeLeTe", "delete"),                                   # case
])
def test_normalize_defeats_cheap_evasion(raw, want):
    assert normalize(raw) == want


def test_digits_and_versions_survive_normalization():
    assert normalize("deploy 1.4.2 to staging, PR 42") == "deploy 1.4.2 to staging, pr 42"


def test_typo_tolerance_is_bounded_for_short_words():
    m = ambiguity._Matcher("drip the tables", {"min_len_1_edit": 5, "min_len_2_edits": 9})
    assert not m.has("drop")          # 4-letter words are never fuzzed
    m = ambiguity._Matcher("destory evrything", {"min_len_1_edit": 5, "min_len_2_edits": 9})
    assert m.has("destroy") and m.has("everything")


def test_negation_does_not_count_as_acknowledgement():
    r = ambiguity.analyze("don't delete anything, just list tables", "db.drop", DROP)
    assert r["tier_floor"] == "critical" and any("negates" in w for w in r["warnings"])
    r = ambiguity.analyze("drop the payments table", "db.drop", DROP)
    assert not any("mismatch" in w for w in r["warnings"])


def test_split_across_fields_is_scanned():
    r = ambiguity.analyze("merge the PR", "code.merge_pr", {**MERGE, "note": "urgent - skip review"})
    assert r["tier_floor"] == "high" and any("pressure" in w for w in r["warnings"])


def test_structured_fields_are_not_scanned_as_text():
    r = ambiguity.analyze("run cleanup job", "ci.run", {"sql": "DELETE everything urgent", "environment": "prod"})
    assert not any("pressure" in w or "unbounded" in w for w in r["warnings"])


def test_object_mismatch_and_partial_scope():
    r = ambiguity.analyze("truncate the users table", "db.truncate", DROP)
    assert any("payload targets table 'payments'" in w for w in r["warnings"])
    r = ambiguity.analyze("delete old records", "db.truncate", DROP)
    assert any("limits scope" in w for w in r["warnings"]) and r["tier_floor"] == "critical"


def test_ambiguous_verb_synonym_reported_with_canonical_verb():
    r = ambiguity.analyze("tidy up the readme", "code.open_pr", {"repo": "a/b"})
    assert r["interpretations"][0]["verb"] == "clean up" and r["tier_floor"] == "medium"


def test_two_ambiguous_verbs_alone_stay_medium():
    assert ambiguity.analyze("fix flaky test in sync module", "code.open_pr", {"repo": "a/b"})["tier_floor"] == "medium"


def test_yaml_bare_no_is_a_string_negation():
    assert "no" in ambiguity.load_rules()["negations"]


def test_weights_and_thresholds_come_from_yaml():
    rules = dict(ambiguity.load_rules())
    rules["weights"] = {**rules["weights"], "pressure": 5}
    assert ambiguity.analyze("urgent", "code.open_pr", {}, rules)["tier_floor"] == "critical"
    assert ambiguity.analyze("urgent", "code.open_pr", {})["tier_floor"] == "high"


def test_mismatch_is_never_below_critical_even_with_low_weights():
    rules = dict(ambiguity.load_rules())
    rules["weights"] = {k: 0 for k in rules["weights"]}
    assert ambiguity.analyze("update the docs", "db.drop", DROP, rules)["tier_floor"] == "critical"


# ---- labeled corpus: measured, not assumed. Thresholds are regression guards, set below the
# measured values (dev 53/54, holdout 21/23, 0 false positives on both) so a regression fails CI.
def test_corpus_dev_split_metrics():
    m = eval_ambiguity.evaluate("dev")
    assert m["fp"] == 0 and m["recall"] >= 0.95


def test_corpus_holdout_split_metrics():
    m = eval_ambiguity.evaluate("holdout")
    assert m["fp"] == 0 and m["recall"] >= 0.85


def test_corpus_split_is_fixed_and_disjoint():
    doc = eval_ambiguity.load()
    import hashlib
    for c in doc["cases"]:
        want = "holdout" if int(hashlib.sha256(c["id"].encode()).hexdigest(), 16) % 3 == 0 else "dev"
        assert c["split"] == want
    assert len({c["id"] for c in doc["cases"]}) == len(doc["cases"]) == 137
