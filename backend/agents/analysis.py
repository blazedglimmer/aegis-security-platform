"""Security Analysis agent — correlate, dedup, score.

The *only* writer of the canonical findings list. It:
  * merges assessment candidates with validation results (validated wins);
  * deduplicates across agents by stable dedup key, merging evidence/agents;
  * computes CVSS 3.1 base scores from each finding's vector *by formula*
    (not by model guess) and aligns severity to the score;
  * sets status: validated→confirmed, unvalidated candidates stay candidate,
    info-level stays informational;
  * optionally asks the LLM to flag likely false positives (advisory only — it
    can lower confidence, never invent or raise a finding).
"""

from __future__ import annotations

from ..domain import Finding, FindingStatus, Severity
from ..orchestrator.state import ScanContext, ScanState
from ..scoring import base_score, severity_for
from .base import BaseAgent


class AnalysisAgent(BaseAgent):
    name = "analysis"
    tool_grant = set()  # no network

    async def run(self, ctx: ScanContext, state: ScanState) -> dict:
        candidates = [Finding(**c) for c in state.get("candidates", [])]
        validated = [Finding(**v) for v in state.get("validated", [])]

        # validated findings override their candidate twins
        by_key: dict[str, Finding] = {}
        for f in candidates:
            self._merge(by_key, f)
        for f in validated:
            f.status = FindingStatus.VALIDATED
            self._merge(by_key, f, prefer=True)

        findings = list(by_key.values())

        # CVSS scoring by formula + severity alignment
        for f in findings:
            if f.cvss_vector:
                try:
                    f.cvss_score = base_score(f.cvss_vector)
                    f.severity = severity_for(f.cvss_score)
                except ValueError:
                    pass
            # status normalization
            if f.status == FindingStatus.VALIDATED:
                f.status = FindingStatus.CONFIRMED
            elif f.severity == Severity.INFO:
                f.status = FindingStatus.INFORMATIONAL

        # optional LLM false-positive triage (advisory)
        await self._llm_triage(ctx, findings)

        findings.sort(key=lambda f: (f.severity.rank, f.cvss_score or 0,
                                     f.status == FindingStatus.CONFIRMED), reverse=True)

        counts = self._counts(findings)
        await ctx.event("status", f"analysis finalized {len(findings)} findings "
                                   f"({counts})", agent=self.name, counts=counts)
        return {"findings": [f.model_dump() for f in findings]}

    def _merge(self, by_key: dict[str, Finding], f: Finding, prefer: bool = False) -> None:
        k = f.dedup_key
        existing = by_key.get(k)
        if existing is None:
            by_key[k] = f
            return
        # merge: keep the stronger record, union agents/evidence/refs
        keep, drop = (f, existing) if (prefer or self._stronger(f, existing)) else (existing, f)
        agents = set(filter(None, [keep.agent, drop.agent]))
        keep.agent = "+".join(sorted(agents))
        keep.references = sorted(set(keep.references) | set(drop.references))
        if drop.evidence and "corroborating" not in keep.evidence:
            keep.evidence = {**keep.evidence, "corroborating": {drop.agent: drop.evidence}}
        if drop.confidence == "high" and keep.confidence != "high":
            keep.confidence = "high"
        by_key[k] = keep

    @staticmethod
    def _stronger(a: Finding, b: Finding) -> bool:
        rank = {"low": 0, "medium": 1, "high": 2}
        if (a.status == FindingStatus.VALIDATED) != (b.status == FindingStatus.VALIDATED):
            return a.status == FindingStatus.VALIDATED
        if a.severity.rank != b.severity.rank:
            return a.severity.rank > b.severity.rank
        return rank[a.confidence] >= rank[b.confidence]

    @staticmethod
    def _counts(findings: list[Finding]) -> dict:
        c = {s.value: 0 for s in Severity}
        for f in findings:
            c[f.severity.value] += 1
        return c

    async def _llm_triage(self, ctx, findings: list[Finding]) -> None:
        if not ctx.llm.available or not findings:
            return
        import json
        payload = [{
            "id": f.id, "title": f.title, "category": f.category,
            "confidence": f.confidence, "status": f.status.value,
            "has_validation": "validation" in f.evidence,
            "evidence_preview": str(f.evidence.get("body_preview", ""))[:400],
        } for f in findings]
        out = await ctx.llm.json_call(
            system="You are a senior application security analyst reviewing findings from an "
                   "AUTHORIZED assessment. Identify which UNVALIDATED, low/medium-confidence "
                   "findings are likely FALSE POSITIVES given the evidence. You may only lower "
                   "confidence or mark likely false positives; never invent findings or raise "
                   "severity. Return ids you judge likely false positives with a reason.",
            user=json.dumps(payload),
            schema_hint='{"likely_false_positives":[{"id":str,"reason":str}]}',
        )
        if not out:
            return
        fp = {x["id"]: x.get("reason", "") for x in out.get("likely_false_positives", []) if "id" in x}
        for f in findings:
            if f.id in fp and f.status != FindingStatus.CONFIRMED and f.confidence != "high":
                f.confidence = "low"
                f.evidence = {**f.evidence, "analyst_note": f"Possible false positive: {fp[f.id]}"}
