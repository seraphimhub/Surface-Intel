#!/usr/bin/env python3
"""God Intel V9 — Headless Recon Mode

Single-file, defensive/passive browser recon tool for authorized testing.
It loads a page in a real headless browser, captures network requests, extracts
candidate endpoints from HTML/JS, classifies responses, and writes a report.

Requirements:
  pip install requests beautifulsoup4
  pip install playwright
  playwright install chromium

Usage:
  python3 god_v9_headless_recon.py -t https://example.com
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


# ---- Optional Playwright import with friendly error -------------------------
try:
    from playwright.async_api import async_playwright
except Exception:  # pragma: no cover
    async_playwright = None


NOISE_SUBSTRINGS = (
    "_next/static",
    "webpack",
    "polyfills",
    "main-app",
    "gtm.js",
    "/favicon",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
)

VALUE_HINTS = (
    "api",
    "auth",
    "session",
    "user",
    "wallet",
    "payment",
    "transactions",
    "kyc",
    "proxy",
    "internal",
    "totp",
    "passkey",
    "order",
    "invoice",
    "account",
)

JS_URL_RE = re.compile(r"https?://[^\"'\s>]+?\.js(?:\?[^\"'\s>]*)?|/[^\"'\s>]+?\.js(?:\?[^\"'\s>]*)?", re.I)
API_RE = re.compile(r"/api/[A-Za-z0-9_\-./]+", re.I)
ABSOLUTE_URL_RE = re.compile(r"https?://[A-Za-z0-9._\-:/?&=%+~#]+", re.I)
NEXTJS_MARKERS = ("__next_f.push", "next-router", "rsc", "data-next-url")


@dataclass
class CapturedRequest:
    url: str
    method: str
    resource_type: str
    status: Optional[int] = None
    content_type: Optional[str] = None
    response_len: Optional[int] = None
    classified: str = "unknown"
    score: int = 0
    reason: str = ""


@dataclass
class ScanState:
    target: str
    home_html: str = ""
    js_assets: Set[str] = field(default_factory=set)
    discovered_urls: Set[str] = field(default_factory=set)
    requests: Dict[str, CapturedRequest] = field(default_factory=dict)
    fingerprint_seen: Set[str] = field(default_factory=set)
    by_kind: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))


class GodV9:
    def __init__(self, target: str, timeout: int = 12, concurrency: int = 8):
        self.state = ScanState(target=target.rstrip("/"))
        self.timeout = timeout
        self.concurrency = concurrency
        self.http = requests.Session()
        self.http.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        })

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------
    def _sha(self, text: str) -> str:
        compact = re.sub(r"\s+", " ", text.strip())
        return hashlib.sha256(compact.encode("utf-8", errors="ignore")).hexdigest()

    def _classify_text(self, text: str, content_type: str = "") -> Tuple[str, int, str]:
        low = (text or "").lower()
        ctype = (content_type or "").lower()

        if any(m in low for m in NEXTJS_MARKERS):
            return "frontend_nextjs", 1, "Next.js/RSC page"
        if ctype.startswith("application/json"):
            return "json_api", 5, "JSON API"
        if "text/html" in ctype:
            return "html_page", 1, "HTML page"
        if low.strip().startswith("{") or low.strip().startswith("["):
            return "json_like", 4, "JSON-like body"
        return "other", 1, "unclassified"

    def _score_url(self, url: str) -> int:
        u = url.lower()
        score = 0
        for hint in VALUE_HINTS:
            if hint in u:
                score += 5
        if "/api/" in u:
            score += 2
        if u.endswith(".js"):
            score += 1
        if any(x in u for x in ("proxy/private", "proxy/public")):
            score += 6
        return score

    def _is_noise(self, url: str) -> bool:
        u = url.lower()
        return any(n in u for n in NOISE_SUBSTRINGS)

    def _is_valuable(self, url: str) -> bool:
        u = url.lower()
        return any(k in u for k in VALUE_HINTS) or "/api/" in u

    def _remember_url(self, url: str):
        if not url:
            return
        if url.startswith("//"):
            url = "https:" + url
        elif url.startswith("/"):
            url = urljoin(self.state.target + "/", url)
        self.state.discovered_urls.add(url)

    def _register(self, url: str, method: str, resource_type: str, status: Optional[int] = None,
                  content_type: Optional[str] = None, response_len: Optional[int] = None,
                  classified: str = "unknown", reason: str = ""):
        key = f"{method}:{url}:{resource_type}"
        if key in self.state.requests:
            return
        self.state.requests[key] = CapturedRequest(
            url=url,
            method=method,
            resource_type=resource_type,
            status=status,
            content_type=content_type,
            response_len=response_len,
            classified=classified,
            score=self._score_url(url),
            reason=reason,
        )
        self.state.by_kind[classified].append(url)

    # ------------------------------------------------------------------
    # HTTP fetches
    # ------------------------------------------------------------------
    def fetch_home(self) -> str:
        print("[+] Fetching homepage")
        r = self._get(self.state.target)
        if not r:
            return ""
        classified, _, reason = self._classify_text(r.text, r.headers.get("content-type", ""))
        self._register(self.state.target, "GET", "document", r.status_code, r.headers.get("content-type"), len(r.text), classified, reason)
        self.state.home_html = r.text
        return r.text

    def _get(self, url: str) -> Optional[requests.Response]:
        try:
            return self.http.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def fetch_wayback(self):
        print("[+] Wayback pass")
        api = (
            "https://web.archive.org/cdx/search/cdx?url="
            f"{requests.utils.quote(self.state.target, safe='')}/*&output=json&fl=original&collapse=urlkey"
        )
        r = self._get(api)
        if not r or r.status_code != 200:
            return
        try:
            data = r.json()
            for row in data[1:]:
                if isinstance(row, list) and row:
                    self._remember_url(row[0])
        except Exception:
            for line in r.text.splitlines():
                line = line.strip()
                if line.startswith("http"):
                    self._remember_url(line)

    # ------------------------------------------------------------------
    # Parse HTML/JS for URLs
    # ------------------------------------------------------------------
    def parse_home(self):
        print("[+] Parsing homepage")
        html = self.state.home_html
        if not html:
            return
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script", src=True):
            self._remember_url(urljoin(self.state.target + "/", tag["src"]))
        for tag in soup.find_all(["a", "link"], href=True):
            href = tag.get("href")
            if href:
                self._remember_url(urljoin(self.state.target + "/", href))
        for u in JS_URL_RE.findall(html):
            self._remember_url(urljoin(self.state.target + "/", u))
        for u in ABSOLUTE_URL_RE.findall(html):
            self._remember_url(u)
        for u in API_RE.findall(html):
            self._remember_url(urljoin(self.state.target + "/", u))

    def fetch_js_assets(self):
        print("[+] Fetching JS assets")
        self.state.js_assets = {u for u in self.state.discovered_urls if u.lower().endswith(".js") and not self._is_noise(u)}
        if not self.state.js_assets:
            return

        for js in sorted(self.state.js_assets):
            r = self._get(js)
            if not r:
                continue
            classified, _, reason = self._classify_text(r.text, r.headers.get("content-type", ""))
            self._register(js, "GET", "js_asset", r.status_code, r.headers.get("content-type"), len(r.text), classified, reason)
            self._extract_from_text(r.text)

    def _extract_from_text(self, text: str):
        for u in JS_URL_RE.findall(text):
            self._remember_url(urljoin(self.state.target + "/", u))
        for u in API_RE.findall(text):
            self._remember_url(urljoin(self.state.target + "/", u))
        for u in ABSOLUTE_URL_RE.findall(text):
            self._remember_url(u)

    # ------------------------------------------------------------------
    # Headless browser capture
    # ------------------------------------------------------------------
    async def headless_capture(self):
        if async_playwright is None:
            print("[!] Playwright not installed; skipping headless capture")
            return

        print("[+] Headless browser capture")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent=self.http.headers.get("User-Agent", "Mozilla/5.0"),
                    viewport={"width": 1440, "height": 900},
                    locale="en-US",
                )
                page = await context.new_page()

                async def on_response(resp):
                    try:
                        url = resp.url
                        if self._is_noise(url):
                            return
                        req = resp.request
                        ctype = resp.headers.get("content-type", "")
                        body_text = ""
                        try:
                            if "application/json" in ctype.lower() or "text/" in ctype.lower() or ctype == "":
                                body_text = await resp.text()
                        except Exception:
                            body_text = ""

                        classified, _, reason = self._classify_text(body_text, ctype)
                        if not self._is_valuable(url) and classified == "html_page":
                            return

                        self._register(
                            url=url,
                            method=req.method,
                            resource_type=req.resource_type,
                            status=resp.status,
                            content_type=ctype,
                            response_len=len(body_text) if body_text else None,
                            classified=classified,
                            reason=reason,
                        )
                        if body_text:
                            self._extract_from_text(body_text)
                            if self._sha(body_text) not in self.state.fingerprint_seen:
                                self.state.fingerprint_seen.add(self._sha(body_text))
                    except Exception:
                        pass

                page.on("response", lambda resp: asyncio.create_task(on_response(resp)))

                try:
                    await page.goto(self.state.target, wait_until="networkidle", timeout=self.timeout * 1000)
                except Exception:
                    try:
                        await page.goto(self.state.target, wait_until="domcontentloaded", timeout=self.timeout * 1000)
                    except Exception:
                        pass

                await page.wait_for_timeout(2500)
                await browser.close()
        except Exception as e:
            print(f"[!] Headless capture skipped: {e}")

    # ------------------------------------------------------------------
    # Candidate filtering and ranking
    # ------------------------------------------------------------------
    def build_candidates(self) -> List[str]:
        candidates = set(self.state.discovered_urls)
        for url in list(candidates):
            if self._is_noise(url):
                candidates.discard(url)
                continue
            if not self._is_valuable(url):
                candidates.discard(url)
        return sorted(candidates)

    def rank_candidates(self, candidates: List[str]) -> List[str]:
        return sorted(candidates, key=lambda u: (self._score_url(u), len(u)), reverse=True)

    def probe_candidates(self, candidates: List[str]):
        print("[+] Lightweight validation")
        # Only probe a small, conservative subset to avoid noise.
        top = self.rank_candidates(candidates)[:120]
        for url in top:
            r = self._get(url)
            if not r:
                continue
            classified, base_score, reason = self._classify_text(r.text, r.headers.get("content-type", ""))
            score = self._score_url(url) + base_score
            if classified == "frontend_nextjs":
                self._register(url, "GET", "frontend", r.status_code, r.headers.get("content-type"), len(r.text), classified, reason)
            else:
                self._register(url, "GET", "candidate", r.status_code, r.headers.get("content-type"), len(r.text), classified, reason)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def write_report(self) -> Path:
        ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        out = Path(f"god-v9-report-{ts}.md")

        ranked = sorted(self.state.requests.values(), key=lambda x: (x.score, x.response_len or 0), reverse=True)
        grouped: Dict[str, List[CapturedRequest]] = defaultdict(list)
        for item in ranked:
            grouped[item.classified].append(item)

        lines: List[str] = []
        lines.append("# God Intel V9 Report")
        lines.append(f"Target: `{self.state.target}`")
        lines.append("")
        lines.append("## Summary")
        lines.append(f"- JS assets: `{len(self.state.js_assets)}`")
        lines.append(f"- Discovered URLs: `{len(self.state.discovered_urls)}`")
        lines.append(f"- Observed requests: `{len(self.state.requests)}`")
        lines.append("")

        for kind in ("json_api", "protected_endpoint", "frontend_nextjs", "html_page", "js_asset", "other", "unknown"):
            items = grouped.get(kind, [])
            if not items:
                continue
            lines.append(f"## {kind}")
            for item in items[:80]:
                lines.append(f"- `{item.url}`")
                lines.append(f"  - score: `{item.score}`")
                if item.status is not None:
                    lines.append(f"  - status: `{item.status}`")
                if item.content_type:
                    lines.append(f"  - content-type: `{item.content_type}`")
                if item.response_len is not None:
                    lines.append(f"  - length: `{item.response_len}`")
                if item.reason:
                    lines.append(f"  - note: {item.reason}")
            lines.append("")

        out.write_text("\n".join(lines), encoding="utf-8")
        return out

    # ------------------------------------------------------------------
    # Main
    # ------------------------------------------------------------------
    def run(self):
        print("🔥 GOD MODE V9 — HEADLESS RECON")
        print(f"Target: {self.state.target}")
        print("[+] Fetching homepage")
        self.fetch_home()
        self.parse_home()
        self.fetch_js_assets()
        self.fetch_wayback()

        # Headless browser capture adds the most value for modern SPA/Next.js apps.
        asyncio.run(self.headless_capture())

        candidates = self.build_candidates()
        print(f"[+] Total discovered URLs: {len(self.state.discovered_urls)}")
        print(f"[+] Candidate URLs after filtering: {len(candidates)}")

        self.probe_candidates(candidates)

        report = self.write_report()
        print(f"[+] Report written: {report}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, help="Base target URL, e.g. https://example.com")
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=12)
    args = parser.parse_args()

    if not args.target.startswith(("http://", "https://")):
        print("[!] Target must start with http:// or https://")
        sys.exit(1)

    tool = GodV9(args.target, timeout=args.timeout, concurrency=args.threads)
    tool.run()


if __name__ == "__main__":
    main()
