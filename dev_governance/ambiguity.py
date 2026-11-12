"""Deterministic language ambiguity analyzer for dev requests (v2: evasion-hardened).

Compares a request's natural-language text (plus free-text payload fields) with its payload using
YAML rules (policies/dev/ambiguity.yaml). Output feeds the advisory report. It can only raise the
tier floor or add warnings - never lower a tier or remove a requirement.

Normalization defeats cheap evasion: NFKC, zero-width/format characters stripped, case folded,
Cyrillic/Greek homoglyphs and leetspeak folded, spaced-out letters re-joined, and per-token typo
tolerance (Damerau-Levenshtein). It is keyword analysis, not understanding: a determined adversary
can still word around it, which is why it can only add friction.
"""
from __future__ import annotations
import os
import re
import unicodedata
from functools import lru_cache
from typing import Optional

import yaml

import tiers as _tiers
from .destructive import classify as _classify

_DEFAULT = os.path.join(os.path.dirname(__file__), "..", "policies", "dev", "ambiguity.yaml")

_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "ν": "v", "ι": "i", "κ": "k", "χ": "x",
    "ı": "i", "ℓ": "l",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_LEET_MULTI = (("|_|", "u"), ("|<", "k"), ("()", "o"), ("/\\", "a"), ("\\/", "v"))
_ZW = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad\u034f\u180e]")


@lru_cache(maxsize=8)
def load_rules(path: Optional[str] = None) -> dict:
    with open(path or os.environ.get("PATIENCE_AMBIGUITY_RULES") or _DEFAULT, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def normalize(text: str) -> str:
    s = unicodedata.normalize("NFKC", text or "")
    s = _ZW.sub("", s)
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Cf")
    s = s.casefold().translate(_HOMOGLYPHS)
    s = "".join(ch for ch in unicodedata.normalize("NFKD", s) if not unicodedata.combining(ch))
    for a, b in _LEET_MULTI:
        s = s.replace(a, b)

    def leet(m):
        w = m.group(0)
        return w.translate(_LEET) if re.search(r"[a-z]", w) and not w.isdigit() else w
    s = re.sub(r"[a-z0-9@$!]+", leet, s)
    # re-join spaced/dotted letters: "d e l e t e", "d.r.o.p", "p-u-r-g-e"
    s = re.sub(r"\b(?:[a-z][ .\-_*]){2,}[a-z]\b", lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def _dl(a: str, b: str, cap: int) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance, early-exit above cap."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[-1]


def _tok(s: str) -> list:
    return re.findall(r"[a-z0-9_*']+|\*", s)


class _Matcher:
    def __init__(self, text: str, fuzzy: dict):
        self.toks = _tok(text)
        self.f1, self.f2 = int(fuzzy.get("min_len_1_edit", 5)), int(fuzzy.get("min_len_2_edits", 9))

    def _eq(self, tok: str, word: str) -> bool:
        if tok == word:
            return True
        n = len(word)
        cap = 2 if n >= self.f2 else (1 if n >= self.f1 else 0)
        return cap > 0 and abs(len(tok) - n) <= cap and tok[:1] == word[:1] and _dl(tok, word, cap) <= cap

    def find(self, phrase: str) -> list:
        """Start indexes where phrase occurs (token-wise, typo tolerant)."""
        p = _tok(str(phrase).casefold())
        if not p:
            return []
        out = []
        for i in range(len(self.toks) - len(p) + 1):
            if all(self._eq(self.toks[i + k], p[k]) for k in range(len(p))):
                out.append(i)
        return out

    def has(self, phrase: str) -> bool:
        return bool(self.find(phrase))


def _rank_of(action: str, interps: list) -> Optional[int]:
    for i, it in enumerate(interps):
        if action in (it.get("actions") or []):
            return i
    return None


def _free_text(payload: dict, fields: list) -> str:
    out = []
    for k, v in (payload or {}).items():
        if isinstance(v, str) and (k in fields or len(v.split()) >= 3) and k not in ("sql", "cmd", "command"):
            out.append(v)
    return " . ".join(out)


def _tier_for(score: float, thresholds: dict) -> str:
    tier = "low"
    for t in ("medium", "high", "critical"):
        if t in thresholds and score >= float(thresholds[t]):
            tier = t
    return tier


def analyze(text: Optional[str], action: str, payload: dict, rules: Optional[dict] = None) -> dict:
    r = rules if rules is not None else load_rules()
    W = {"ambiguous_verb": 1, "unbounded_scope": 2, "pressure": 2, "negated_destructive": 4, "mismatch": 4,
         "object_mismatch": 4, **(r.get("weights") or {})}
    TH = r.get("thresholds") or {"medium": 1, "high": 2, "critical": 4}
    legacy_tiers = r.get("tiers")  # v1 rule files: per-signal tiers instead of weights
    fuzzy = r.get("fuzzy") or {}
    raw_text = text or ""
    t = normalize(raw_text)
    extra = normalize(_free_text(payload, r.get("free_text_fields") or []))
    warnings, unknowns, basis, verbs, signals = [], [], [], [], []
    if not t and not extra:
        unknowns.append("intent: no natural-language text supplied; cannot check text vs payload")
        return {"version": r.get("version"), "tier_floor": "low", "warnings": warnings,
                "unknowns": unknowns, "interpretations": [], "basis": ["no text"], "confidence": "low",
                "score": 0, "normalized": ""}
    mt = _Matcher(t, fuzzy)                      # request text only (acknowledgement)
    ma = _Matcher((t + " . " + extra).strip(" ."), fuzzy)  # text + free-text payload fields
    if normalize(raw_text) != raw_text.casefold().strip():
        basis.append("text normalized (unicode/zero-width/homoglyph/leet/spacing)")
    destructive = bool(_classify(action, payload or {}))

    def hit(sig, msg, tier_key=None):
        signals.append(sig)
        warnings.append(msg)

    syn = r.get("verb_synonyms") or {}
    for verb, interps in (r.get("ambiguous_verbs") or {}).items():
        forms = [verb] + list(syn.get(verb) or [])
        found = next((f for f in forms if ma.has(f)), None)
        if not found:
            continue
        rank = _rank_of(action, interps)
        ranked = [{"rank": i, "meaning": it["meaning"], "matches_payload": i == rank}
                  for i, it in enumerate(interps)]
        verbs.append({"verb": verb, "matched": found, "interpretations": ranked, "payload_rank": rank})
        hit("ambiguous_verb", f"ambiguous verb '{verb}'" + (f" (as '{found}')" if found != verb else "")
            + f": {len(interps)} readings")
        basis.append(f"verb rule '{verb}'")
        if rank is None:
            unknowns.append(f"payload action {action!r} matches no listed reading of '{verb}'")
        elif rank == len(interps) - 1 and len(interps) > 1:
            hit("mismatch", f"mismatch: payload takes the MOST destructive reading of '{verb}'")

    scope_hits = [w for w in (r.get("unbounded_scope") or []) if ma.has(w)]
    limits = [w for w in (r.get("scope_limits") or []) if ma.has(w)]
    if scope_hits:
        hit("unbounded_scope", f"unbounded scope wording: {', '.join(scope_hits)}")
        basis.append("scope rule")
    if (scope_hits or destructive) and not limits:
        unknowns.append("scope limit: text names no table/repo/date/id bound")

    pressure = [w for w in (r.get("pressure") or []) if ma.has(w)]
    if pressure:
        hit("pressure", f"pressure/coercion wording: {', '.join(pressure)} (does not shorten review)")
        basis.append("pressure rule")

    # destructive acknowledgement in the TEXT, minus negated mentions ("don't delete anything")
    negs, win = r.get("negations") or [], int(r.get("negation_window", 3))
    neg_idx = sorted({i for n in negs for i in mt.find(n)})
    ack, negated = [], []
    for w in (r.get("destructive_words") or []):
        for i in mt.find(w):
            (negated if any(0 < i - j <= win for j in neg_idx) else ack).append(w)
    if destructive:
        if negated and not ack:
            hit("negated_destructive",
                f"mismatch: text negates destructive intent ({', '.join(sorted(set(negated)))}) but payload is destructive")
            basis.append("negation rule")
        elif not ack and not scope_hits:
            # an ambiguous verb ("clean up", "tidy") is NOT an acknowledgement of destruction
            hit("mismatch", "mismatch: payload is destructive but the text does not say so")
            basis.append("text-vs-payload rule")
        # object mismatch: text names a table that is not the payload's table
        tbl = str((payload or {}).get("table") or "").casefold()
        stop = set(r.get("object_stopwords") or [])
        named = re.findall(r"([a-z0-9_]+) table", t) + re.findall(r"table ([a-z0-9_]+)", t) + \
            re.findall(r"from ([a-z0-9_]+)", t)
        named = [n for n in named if n not in stop]
        if tbl and named and ack and not any(n == tbl or n.rstrip("s") == tbl.rstrip("s") for n in named):
            hit("object_mismatch", f"mismatch: text names {named[0]!r} but payload targets table {tbl!r}")
        # partial-scope wording ("old records") vs a whole-object action (truncate/drop/wipe)
        if action in (r.get("whole_object_actions") or []):
            quals, nouns = r.get("subset_qualifiers") or [], r.get("row_nouns") or []
            for q in quals:
                for i in mt.find(q):
                    if any(mt._eq(tok, n) for tok in mt.toks[i + 1:i + 3] for n in nouns):
                        hit("mismatch", f"mismatch: text limits scope ('{q} ...') but {action} affects the whole object")
                        break
    br = (payload or {}).get("blast_radius") or {}
    if isinstance(br, dict) and (br.get("rows", 0) or 0) > 100 and ma.has("a few") | ma.has("single") | ma.has("one"):
        hit("mismatch", f"mismatch: text implies small scope but payload declares {br['rows']} rows")

    if legacy_tiers is not None and r.get("weights") is None:
        floor = "low"
        for s in signals:
            key = "mismatch" if s in ("negated_destructive", "object_mismatch") else s
            floor = _tiers.max_tier(floor, legacy_tiers.get(key, "high"))
        score = len(signals)
    else:
        score = sum(float(W.get(s, 0)) for s in signals)
        floor = _tier_for(score, TH)
        if any(s in ("mismatch", "negated_destructive", "object_mismatch") for s in signals):
            floor = _tiers.max_tier(floor, "critical")  # a text/payload mismatch is never below critical
    confidence = "high" if not unknowns and not verbs else ("medium" if len(unknowns) <= 1 else "low")
    return {"version": r.get("version"), "tier_floor": floor, "warnings": warnings,
            "unknowns": unknowns, "interpretations": verbs, "basis": basis or ["no rule matched"],
            "confidence": confidence, "score": score, "signals": signals, "normalized": t}
