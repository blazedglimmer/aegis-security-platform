"""Playwright crawler — optional, read-only, scope-enforced at the browser.

Renders JS-heavy apps to discover links, forms, and XHR/fetch API endpoints the
static crawler misses. Scope is enforced *inside the browser*: a request route
handler aborts any navigation or sub-request that is out of scope or not
http(s), so the headless browser cannot be steered off-target.

Read-only: it never submits forms or clicks destructive controls during recon;
it observes the DOM and the network. If Playwright or its browser isn't
available, :attr:`available` is False and recon falls back to the static crawler.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..domain import Endpoint
from ..safety.scope import ScopeSpec


@dataclass
class CrawlResult:
    endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    api_calls: list[Endpoint] = field(default_factory=list)
    rendered_html: dict[str, str] = field(default_factory=dict)


class BrowserCrawler:
    def __init__(self, scope: ScopeSpec, *, enabled: bool = True):
        self.scope = scope
        self.enabled = enabled
        self._pw_ok = self._detect() if enabled else False

    @staticmethod
    def _detect() -> bool:
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False

    @property
    def available(self) -> bool:
        return self._pw_ok

    async def crawl(self, start_url: str, *, max_pages: int = 20) -> CrawlResult:
        result = CrawlResult()
        if not self.available or not self.scope.is_in_scope(start_url):
            return result
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return result

        seen: set[str] = set()
        queue = [start_url]

        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(
                    headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
                )
            except Exception:
                return result
            context = await browser.new_context(
                user_agent="Aegis-Scanner/0.1 (+authorized-assessment)",
                ignore_https_errors=False,
            )

            scope = self.scope

            async def route_handler(route):
                req = route.request
                url = req.url
                if not scope.is_in_scope(url):
                    # Record cross-origin API calls as observations, but don't fetch.
                    await route.abort()
                    return
                await route.continue_()

            await context.route("**/*", route_handler)

            page = await context.new_page()
            captured: list[Endpoint] = []

            def on_request(req):
                if req.resource_type in ("xhr", "fetch") and scope.is_in_scope(req.url):
                    captured.append(Endpoint(url=req.url, method=req.method, source="api"))

            page.on("request", on_request)

            while queue and len(seen) < max_pages:
                url = queue.pop(0)
                if url in seen or not scope.is_in_scope(url):
                    continue
                seen.add(url)
                try:
                    resp = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    continue
                status = resp.status if resp else None
                ctype = (resp.headers.get("content-type") if resp else "") or ""
                result.endpoints.append(Endpoint(url=url, status=status, content_type=ctype, source="crawl"))
                try:
                    result.rendered_html[url] = (await page.content())[:200_000]
                except Exception:
                    pass

                # extract links
                try:
                    hrefs = await page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)"
                    )
                except Exception:
                    hrefs = []
                for h in hrefs:
                    if scope.is_in_scope(h) and h not in seen and len(seen) + len(queue) < max_pages * 3:
                        queue.append(h.split("#")[0])

                # extract forms
                try:
                    forms = await page.eval_on_selector_all(
                        "form",
                        """els => els.map(f => ({
                            action: f.action, method: (f.method||'get').toLowerCase(),
                            inputs: Array.from(f.querySelectorAll('input,select,textarea'))
                                .map(i => ({name: i.name, type: i.type}))
                        }))""",
                    )
                except Exception:
                    forms = []
                for f in forms:
                    if f.get("action") and scope.is_in_scope(f["action"]):
                        result.forms.append(f)

            await browser.close()

        # dedupe api calls
        seen_api = set()
        for ep in captured:
            if ep.key not in seen_api:
                seen_api.add(ep.key)
                result.api_calls.append(ep)
        return result
