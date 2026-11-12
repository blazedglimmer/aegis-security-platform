"""Recon agent — map the authorized target's surface from real responses.

Discovers endpoints via homepage crawl, robots.txt, sitemap.xml, and (when
available) a Playwright render to catch JS routes and XHR/fetch API calls.
Fingerprints technologies from headers and body markers. Probes a short list of
sensitive paths with single safe GETs. Everything is evidence-backed; the LLM,
if present, only *categorizes* and proposes leads that are re-verified.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

from ..domain import Endpoint, Finding, Lead, Tech
from ..orchestrator.state import ScanContext, ScanState
from ..tools import signatures
from ..tools.browser import BrowserCrawler
from .base import BaseAgent

_TECH_HEADER_MARKERS = {
    "server": "server",
    "x-powered-by": "framework",
    "x-aspnet-version": "framework",
    "x-generator": "cms",
    "via": "cdn",
    "x-drupal-cache": "cms",
}
_BODY_MARKERS = [
    (r"wp-content|wp-includes", "WordPress", "cms"),
    (r"Drupal.settings|/sites/default/files", "Drupal", "cms"),
    (r"__NEXT_DATA__", "Next.js", "framework"),
    (r"ng-version=", "Angular", "framework"),
    (r"data-reactroot|react-dom", "React", "framework"),
    (r"csrf-token", "has-CSRF-token", "security"),
    (r"/_nuxt/", "Nuxt.js", "framework"),
    (r"Shopify\.", "Shopify", "cms"),
]


class ReconAgent(BaseAgent):
    name = "recon"
    tool_grant = {"http", "browser", "dns"}

    async def run(self, ctx: ScanContext, state: ScanState) -> dict:
        target = state["target_url"]
        endpoints: dict[str, Endpoint] = {}
        tech: dict[str, Tech] = {}
        candidates: list[Finding] = []
        leads: list[Lead] = []

        client = ctx.new_client()
        try:
            # 1) homepage
            home = await client.get(target)
            endpoints[target] = Endpoint(url=target, status=home.status,
                                         content_type=home.response_headers.get("content-type"))
            self._fingerprint(home, tech)
            candidates.extend(signatures.run_passive(home))
            await ctx.event("log", f"fetched homepage ({home.status})", agent=self.name)

            # 2) links from homepage
            for href in self._extract_links(target, home.text):
                if ctx.scope.is_in_scope(href):
                    endpoints.setdefault(href, Endpoint(url=href, source="link"))

            # 3) robots.txt + sitemap.xml
            await self._robots_and_sitemap(ctx, client, target, endpoints)

            # 4) sensitive paths (one safe GET each)
            base = f"{urlsplit(target).scheme}://{urlsplit(target).netloc}"
            for path in signatures.SENSITIVE_PATHS:
                if not await ctx.ledger.claim(self.name, "sensitive_path", base + path):
                    continue
                try:
                    ex = await client.get(base + path)
                except Exception:
                    continue
                candidates.extend(signatures.check_sensitive_path(ex, path))
                if path in ("/api/swagger.json", "/openapi.json", "/swagger/v1/swagger.json") and ex.status == 200:
                    leads.append(Lead(kind="openapi_spec", target=base + path,
                                      rationale="OpenAPI/Swagger spec exposed", suggested_agent="api"))
        finally:
            await client.aclose()

        # 5) browser render (optional)
        crawler = BrowserCrawler(ctx.scope, enabled=ctx.settings.enable_playwright)
        if crawler.available:
            await ctx.event("log", "rendering with headless browser", agent=self.name)
            cr = await crawler.crawl(target, max_pages=15)
            for ep in cr.endpoints + cr.api_calls:
                endpoints.setdefault(ep.url, ep)
            for f in cr.forms:
                leads.append(Lead(kind="form", target=f.get("action", target),
                                  rationale=f"form ({f.get('method')}) with inputs "
                                            f"{[i.get('name') for i in f.get('inputs', [])]}",
                                  suggested_agent="authz" if self._looks_like_login(f) else "web_vuln"))
            if cr.api_calls:
                leads.append(Lead(kind="api_traffic", target=target,
                                  rationale=f"{len(cr.api_calls)} XHR/fetch API endpoints observed",
                                  suggested_agent="api"))

        # 6) optional LLM categorization of tech → leads (verified, non-authoritative)
        await self._llm_leads(ctx, tech, list(endpoints.values()), leads)

        await ctx.event("status", f"recon mapped {len(endpoints)} endpoints, "
                                   f"{len(tech)} technologies", agent=self.name,
                        endpoints=len(endpoints), tech=len(tech))

        return {
            "tech": [t.model_dump() for t in tech.values()],
            "endpoints": [e.model_dump() for e in endpoints.values()],
            "candidates": [c.model_dump() for c in candidates],
            "leads": [l.model_dump() for l in leads],
        }

    # --- helpers ---
    def _fingerprint(self, ex, tech: dict[str, Tech]) -> None:
        h = {k.lower(): v for k, v in ex.response_headers.items()}
        for header, category in _TECH_HEADER_MARKERS.items():
            if header in h:
                name = h[header]
                tech[name] = Tech(name=name, category=category, evidence=f"{header}: {name}")
        body = ex.text
        for pattern, name, category in _BODY_MARKERS:
            if re.search(pattern, body, re.I):
                tech[name] = Tech(name=name, category=category, evidence=f"body matches /{pattern}/")

    @staticmethod
    def _extract_links(base: str, html: str) -> list[str]:
        out = []
        for m in re.finditer(r'href=["\']([^"\'#]+)', html, re.I):
            href = m.group(1).strip()
            if href.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            out.append(urljoin(base, href))
        return out

    async def _robots_and_sitemap(self, ctx, client, target, endpoints) -> None:
        base = f"{urlsplit(target).scheme}://{urlsplit(target).netloc}"
        try:
            robots = await client.get(base + "/robots.txt")
            if robots.status == 200:
                for m in re.finditer(r"(?:Allow|Disallow|Sitemap):\s*(\S+)", robots.text, re.I):
                    val = m.group(1)
                    url = val if val.startswith("http") else urljoin(base, val)
                    if ctx.scope.is_in_scope(url):
                        endpoints.setdefault(url, Endpoint(url=url, source="robots"))
        except Exception:
            pass
        for sm in ("/sitemap.xml", "/sitemap_index.xml"):
            try:
                r = await client.get(base + sm)
                if r.status == 200 and "xml" in (r.response_headers.get("content-type", "")):
                    for loc in self._parse_sitemap(r.text):
                        if ctx.scope.is_in_scope(loc):
                            endpoints.setdefault(loc, Endpoint(url=loc, source="sitemap"))
            except Exception:
                continue

    @staticmethod
    def _parse_sitemap(xml: str) -> list[str]:
        try:
            root = ElementTree.fromstring(xml)
        except ElementTree.ParseError:
            return []
        return [el.text.strip() for el in root.iter() if el.tag.endswith("loc") and el.text]

    @staticmethod
    def _looks_like_login(form: dict) -> bool:
        names = " ".join((i.get("name") or "") + (i.get("type") or "") for i in form.get("inputs", []))
        return "password" in names.lower()

    async def _llm_leads(self, ctx, tech, endpoints, leads) -> None:
        if not ctx.llm.available:
            return
        from ..tools.llm import wrap_untrusted
        summary = {
            "technologies": [t.model_dump() for t in tech.values()],
            "sample_endpoints": [e.url for e in endpoints[:40]],
        }
        import json as _json
        out = await ctx.llm.json_call(
            system="You are a reconnaissance analyst for an AUTHORIZED web security "
                   "assessment. Given discovered technologies and endpoints, propose up to 6 "
                   "specific, non-destructive follow-up checks another agent should perform. "
                   "Base them only on the provided data.",
            user=wrap_untrusted("recon_summary", _json.dumps(summary)),
            schema_hint='{"leads":[{"kind":str,"target":str,"rationale":str,"suggested_agent":'
                        '"web_vuln|authz|api"}]}',
        )
        if out and isinstance(out.get("leads"), list):
            for l in out["leads"][:6]:
                tgt = l.get("target", "")
                if tgt and ctx.scope.is_in_scope(tgt if "://" in tgt else "https://" + tgt):
                    leads.append(Lead(kind=str(l.get("kind", "llm")), target=tgt,
                                      rationale=str(l.get("rationale", ""))[:300],
                                      suggested_agent=l.get("suggested_agent")))
