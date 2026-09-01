"""Validate that a finding's cited `standards` are real corpus references.

Each Finding carries a `standards` list (e.g. ``MASVS-CRYPTO-2``, ``Course:M10``)
that the model is instructed to fill only with labels it actually retrieved via
`search_knowledge`. Nothing enforced that, so the model could assert a plausible
but never-retrieved control id — a subtle, hard-to-spot hallucination that makes
the report look better grounded than it is.

This is the CHEAP validation pass (per the decision log): check each cited label
against the set of refs that genuinely exist in the knowledge base, and drop any
that don't. It can't yet prove a finding *retrieved* that specific ref (the FULL
fix — per-finding retrieval tracking — is a later refinement), but it does
guarantee every surviving citation is a real, resolvable corpus reference.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import AnalysisReport


@dataclass
class CitationAudit:
    kept: int = 0                               # citations that resolved to a real ref
    dropped: list[tuple[str, str]] = field(default_factory=list)  # (finding_title, bad_ref)

    @property
    def n_dropped(self) -> int:
        return len(self.dropped)


def _split_refs(raw: str) -> list[str]:
    """A list item should be one ref, but tolerate 'A, B' or trailing punctuation."""
    return [p.strip().strip(".;") for p in re.split(r"[,;]", raw) if p.strip().strip(".;")]


def validate_report(report: AnalysisReport, valid_refs: set[str]) -> CitationAudit:
    """Strip any cited standard that isn't a real corpus ref. Mutates each finding's
    `standards` in place (canonical casing preserved) and returns an audit."""
    canonical = {r.lower(): r for r in valid_refs}
    audit = CitationAudit()

    for f in report.findings:
        cleaned: list[str] = []
        for item in f.standards:
            for ref in _split_refs(item):
                canon = canonical.get(ref.lower())
                if canon is not None:
                    if canon not in cleaned:
                        cleaned.append(canon)
                    audit.kept += 1
                else:
                    audit.dropped.append((f.title, ref))
        f.standards = cleaned

    return audit
