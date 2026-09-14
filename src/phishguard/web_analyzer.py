"""Safe and optional webpage heuristic analyzer.

Performs non-intrusive, read-only inspection of live webpage metadata,
login inputs, and forms. Always fails safely if the target is offline or unreachable.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from phishguard.features import SUSPICIOUS_KEYWORDS

WEB_ANALYSIS_TIMEOUT = 3.0  # Strict timeout in seconds to keep CLI snappy
MAX_RESPONSE_BYTES = 256 * 1024  # 256 KB limit to prevent large payload downloads


@dataclass
class WebAnalysisResult:
    """Structured findings from safe webpage inspection."""

    is_accessible: bool
    status_code: Optional[int] = None
    title: Optional[str] = None
    has_login_form: bool = False
    has_password_input: bool = False
    external_links_count: int = 0
    matched_keywords: List[str] = field(default_factory=list)
    signals: List[str] = field(default_factory=list)
    error_message: Optional[str] = None


def analyze_webpage(url: str, timeout_sec: float = WEB_ANALYSIS_TIMEOUT) -> WebAnalysisResult:
    """Safely inspect live webpage content for phishing cues without executing or submitting anything.

    Fails gracefully with is_accessible=False if the target is unreachable or offline.
    """
    clean_url = url if "://" in url else f"http://{url}"

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml",
    }

    try:
        response = requests.get(
            clean_url,
            headers=headers,
            timeout=timeout_sec,
            allow_redirects=True,
            stream=True,
            verify=False,  # Allow inspection of sites with self-signed certs common in phishing
        )
        # Read limited chunk to inspect HTML head and body
        raw_content = response.raw.read(MAX_RESPONSE_BYTES)
        html_text = raw_content.decode("utf-8", errors="ignore")
    except Exception as exc:
        return WebAnalysisResult(
            is_accessible=False,
            error_message=f"Web analysis unavailable (site unreachable/offline: {type(exc).__name__})",
        )

    try:
        soup = BeautifulSoup(html_text, "html.parser")
    except Exception:
        return WebAnalysisResult(
            is_accessible=False,
            error_message="Web analysis unavailable (unable to parse HTML content)",
        )

    # 1. Page title
    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else None

    # 2. Password input fields
    password_inputs = soup.find_all("input", attrs={"type": lambda t: t and t.lower() == "password"})
    has_password_input = len(password_inputs) > 0

    # 3. Forms inspection (check if any form has login/auth clues)
    forms = soup.find_all("form")
    has_login_form = False
    for form in forms:
        action = str(form.get("action", "")).lower()
        inputs = [inp.get("name", "") for inp in form.find_all("input")]
        input_str = " ".join(str(i).lower() for i in inputs)
        if has_password_input or "login" in action or "signin" in action or "pass" in input_str:
            has_login_form = True
            break

    # 4. Suspicious keywords in visible text
    body_text = soup.get_text(separator=" ", strip=True).lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in body_text]

    # 5. External links count
    parsed_base = urlparse(clean_url)
    base_domain = parsed_base.netloc.lower()
    external_links_count = 0

    for link in soup.find_all("a", href=True):
        href = link["href"]
        if href.startswith("http://") or href.startswith("https://"):
            link_domain = urlparse(href).netloc.lower()
            if link_domain and base_domain not in link_domain:
                external_links_count += 1

    # Security signals derived from live DOM
    signals: List[str] = []
    if has_password_input:
        signals.append("[HIGH] Detected password input field on webpage")
    if has_login_form:
        signals.append("[MEDIUM] Webpage contains interactive authentication/login form")
    if len(matched_keywords) >= 3:
        signals.append(
            f"[MEDIUM] High concentration of credential keywords on page ({len(matched_keywords)})"
        )
    if external_links_count > 10:
        signals.append(
            f"[LOW] Webpage includes multiple external cross-domain links ({external_links_count})"
        )

    return WebAnalysisResult(
        is_accessible=True,
        status_code=response.status_code,
        title=title[:60] if title else None,
        has_login_form=has_login_form,
        has_password_input=has_password_input,
        external_links_count=external_links_count,
        matched_keywords=matched_keywords[:6],
        signals=signals,
        error_message=None,
    )
