"""Reporting agent — assemble the assessment report in json/md/html.

Report structure: executive summary, scope & authorization, severity breakdown,
then per-finding technical detail (severity, CVSS, affected endpoint, evidence,
reproduction, impact, remediation). The LLM, if present, writes the executive
summary prose over the computed facts; otherwise a deterministic template is
used. Numbers and severities always come from the analysis agent, never the LLM.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from ..domain import Finding, FindingStatus, Severity
from ..orchestrator.state import ScanContext, ScanState
from .base import BaseAgent

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_COLOR = {"critical": "#7f1d1d", "high": "#b91c1c", "medium": "#c2410c",
              "low": "#a16207", "info": "#475569"}


class ReportingAgent(BaseAgent):
    name = "reporting"
    tool_grant = set()

    async def run(self, ctx: ScanContext, state: ScanState) -> dict:
        findings = [Finding(**f) for f in state.get("findings", [])]
        counts = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}
        confirmed = [f for f in findings if f.status == FindingStatus.CONFIRMED]

        summary = await self._exec_summary(ctx, state, findings, counts, confirmed)

        meta = {
            "scan_id": state["scan_id"],
            "target": state["target_url"],
            "authorization_id": state.get("authorization_id"),
            "scope": ctx.scope.describe(),
            "profile": state.get("profile"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "audit_log_verified": ctx.audit.verify(),
            "counts": counts,
            "total": len(findings),
            "confirmed": len(confirmed),
        }

        rd = ctx.settings.reports_dir
        rd.mkdir(parents=True, exist_ok=True)
        stem = state["scan_id"]
        json_path = rd / f"{stem}.json"
        md_path = rd / f"{stem}.md"
        html_path = rd / f"{stem}.html"

        report_obj = {"meta": meta, "executive_summary": summary,
                      "findings": [f.model_dump(mode="json") for f in findings]}
        json_path.write_text(json.dumps(report_obj, indent=2, default=str))
        md_path.write_text(self._markdown(meta, summary, findings))
        html_path.write_text(self._html(meta, summary, findings))

        await ctx.event("status", "report generated", agent=self.name,
                        paths={"json": str(json_path), "md": str(md_path), "html": str(html_path)})
        return {"report_paths": {"json": str(json_path), "md": str(md_path), "html": str(html_path)}}

    async def _exec_summary(self, ctx, state, findings, counts, confirmed) -> str:
        facts = (f"Target {state['target_url']} assessed with profile "
                 f"'{state.get('profile')}'. {len(findings)} findings "
                 f"({counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
                 f"{counts['low']} low, {counts['info']} info); {len(confirmed)} confirmed via "
                 f"non-destructive validation.")
        if ctx.llm.available:
            prose = await ctx.llm.text_call(
                system="You are writing the executive summary of an AUTHORIZED web security "
                       "assessment for a mixed technical/non-technical audience. Be precise and "
                       "non-sensational. Use ONLY the facts provided; do not invent findings or "
                       "numbers. 120-180 words.",
                user=facts + "\n\nTop findings:\n" + "\n".join(
                    f"- [{f.severity.value}] {f.title} ({f.status.value})" for f in findings[:8]),
                max_tokens=400,
            )
            if prose:
                return prose
        # deterministic fallback
        top = "; ".join(f"{f.title} ({f.severity.value})" for f in findings[:5]) or "no notable issues"
        return (facts + f" The most significant issues: {top}. All active testing was "
                "non-destructive and confined to the authorized scope. See technical findings "
                "for evidence, reproduction, and remediation.")

    # ---------- markdown ----------
    def _markdown(self, meta, summary, findings) -> str:
        L = []
        L.append(f"# Security Assessment Report — {meta['target']}\n")
        L.append(f"- **Scan ID:** {meta['scan_id']}")
        L.append(f"- **Authorization:** {meta['authorization_id']}")
        L.append(f"- **Scope:** {meta['scope']}")
        L.append(f"- **Profile:** {meta['profile']}")
        L.append(f"- **Generated:** {meta['generated_at']}")
        L.append(f"- **Audit log integrity:** {'VERIFIED' if meta['audit_log_verified'] else 'FAILED'}\n")
        L.append("## Executive Summary\n")
        L.append(summary + "\n")
        L.append("## Severity Breakdown\n")
        L.append("| Severity | Count |\n|---|---|")
        for s in _SEV_ORDER:
            L.append(f"| {s.value.title()} | {meta['counts'][s.value]} |")
        L.append(f"\n**Total:** {meta['total']}  |  **Confirmed:** {meta['confirmed']}\n")
        L.append("## Technical Findings\n")
        for i, f in enumerate(findings, 1):
            L.append(f"### {i}. {f.title}")
            L.append(f"- **Severity:** {f.severity.value.title()}"
                     + (f" (CVSS {f.cvss_score} — `{f.cvss_vector}`)" if f.cvss_score is not None else ""))
            L.append(f"- **Status:** {f.status.value}  |  **Confidence:** {f.confidence}  "
                     f"|  **Category:** {f.category}  |  **Agent:** {f.agent}")
            if f.endpoint:
                L.append(f"- **Affected endpoint:** `{f.endpoint}`")
            L.append(f"\n{f.description}\n")
            if f.impact:
                L.append(f"**Impact:** {f.impact}\n")
            if f.reproduction:
                L.append("**Reproduction:**")
                L.extend(f"  {step}" for step in f.reproduction)
                L.append("")
            if f.remediation:
                L.append(f"**Remediation:** {f.remediation}\n")
            if f.references:
                L.append("**References:** " + ", ".join(f.references) + "\n")
            ev = {k: v for k, v in f.evidence.items() if k not in ("body_preview",)}
            if ev:
                L.append("<details><summary>Evidence</summary>\n\n```json")
                L.append(json.dumps(ev, indent=2, default=str)[:3000])
                L.append("```\n</details>\n")
        return "\n".join(L)

    # ---------- html ----------
    def _html(self, meta, summary, findings) -> str:
        rows = "".join(
            f'<tr><td><span class="pill" style="background:{_SEV_COLOR[s.value]}">'
            f'{s.value.title()}</span></td><td>{meta["counts"][s.value]}</td></tr>'
            for s in _SEV_ORDER
        )
        cards = []
        for i, f in enumerate(findings, 1):
            cvss = (f" &middot; CVSS {f.cvss_score} <code>{html.escape(f.cvss_vector or '')}</code>"
                    if f.cvss_score is not None else "")
            repro = ("<ol>" + "".join(f"<li>{html.escape(s)}</li>" for s in f.reproduction) + "</ol>"
                     if f.reproduction else "")
            ev = {k: v for k, v in f.evidence.items() if k != "body_preview"}
            cards.append(f"""
            <div class="card">
              <div class="chead">
                <span class="pill" style="background:{_SEV_COLOR[f.severity.value]}">{f.severity.value.title()}</span>
                <h3>{i}. {html.escape(f.title)}</h3>
              </div>
              <div class="meta">{f.status.value} &middot; {f.confidence} confidence &middot;
                 {html.escape(f.category)} &middot; {html.escape(f.agent)}{cvss}</div>
              {f'<div class="endpoint"><code>{html.escape(f.endpoint)}</code></div>' if f.endpoint else ''}
              <p>{html.escape(f.description).replace(chr(10), '<br>')}</p>
              {f'<p><b>Impact:</b> {html.escape(f.impact)}</p>' if f.impact else ''}
              {f'<div><b>Reproduction</b>{repro}</div>' if repro else ''}
              {f'<p><b>Remediation:</b> {html.escape(f.remediation)}</p>' if f.remediation else ''}
              <details><summary>Evidence</summary><pre>{html.escape(json.dumps(ev, indent=2, default=str)[:3000])}</pre></details>
            </div>""")
        integrity = "VERIFIED" if meta["audit_log_verified"] else "FAILED"
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aegis Report — {html.escape(meta['target'])}</title>
<style>
 body{{font:15px/1.6 system-ui,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}}
 .wrap{{max-width:900px;margin:0 auto;padding:32px 20px}}
 h1{{font-size:24px}} h3{{margin:0;font-size:17px}}
 .sub{{color:#94a3b8;font-size:13px}}
 table{{border-collapse:collapse;margin:12px 0}} td{{padding:4px 12px;border-bottom:1px solid #1e293b}}
 .pill{{color:#fff;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600}}
 .card{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px;margin:14px 0}}
 .chead{{display:flex;gap:10px;align-items:center}} .meta{{color:#94a3b8;font-size:12px;margin:6px 0}}
 .endpoint code,code{{background:#0b1220;color:#7dd3fc;padding:1px 6px;border-radius:5px;font-size:12px;word-break:break-all}}
 pre{{background:#0b1220;padding:12px;border-radius:8px;overflow:auto;font-size:12px}}
 details summary{{cursor:pointer;color:#38bdf8}}
 .banner{{background:#422006;border:1px solid #a16207;border-radius:8px;padding:10px 14px;font-size:13px}}
</style></head><body><div class="wrap">
<h1>Security Assessment Report</h1>
<p class="sub">{html.escape(meta['target'])} &middot; scan {meta['scan_id']} &middot; {meta['generated_at']}</p>
<div class="banner">Authorized assessment. Scope: {html.escape(meta['scope'])} &middot;
 profile {meta['profile']} &middot; audit-log integrity: <b>{integrity}</b></div>
<h2>Executive Summary</h2><p>{html.escape(summary)}</p>
<h2>Severity Breakdown</h2><table>{rows}</table>
<p class="sub">Total {meta['total']} &middot; Confirmed {meta['confirmed']}</p>
<h2>Technical Findings</h2>{''.join(cards) or '<p>No findings.</p>'}
</div></body></html>"""
