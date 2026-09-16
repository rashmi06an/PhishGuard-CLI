"""Safe and optional webpage heuristic analyzer.

Performs non-intrusive, read-only inspection of live webpage metadata,
login inputs, and forms. Always fails safely if the target is offline or unreachable.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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


@dataclass
class ContentSimilarityResult:
    """Structured result of backend code / content similarity between two webpages."""

    genuine_target: str
    suspicious_target: str
    content_similarity_score: float  # 0.0 to 100.0%
    similarity_probability: float  # 0.0 to 1.0 (more similarity -> higher lookalike probability)
    is_content_lookalike: bool
    verdict: str
    dom_similarity: float
    form_similarity: float
    title_similarity: float
    text_similarity: float
    signals: List[str] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self):
        return {
            "genuine_target": self.genuine_target,
            "suspicious_target": self.suspicious_target,
            "content_similarity_score": round(self.content_similarity_score, 2),
            "similarity_probability": round(self.similarity_probability, 4),
            "is_content_lookalike": self.is_content_lookalike,
            "verdict": self.verdict,
            "dom_similarity": round(self.dom_similarity, 2),
            "form_similarity": round(self.form_similarity, 2),
            "title_similarity": round(self.title_similarity, 2),
            "text_similarity": round(self.text_similarity, 2),
            "signals": self.signals,
            "error_message": self.error_message,
        }


def _get_html(source: str, timeout_sec: float = WEB_ANALYSIS_TIMEOUT) -> Optional[str]:
    """Retrieve HTML text from raw HTML string, file path, or live URL."""
    source_clean = source.strip()
    if "<html" in source_clean.lower() or "<!doctype" in source_clean.lower() or "<body" in source_clean.lower():
        return source_clean

    import os
    if os.path.isfile(source_clean):
        try:
            with open(source_clean, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception:
            return None

    clean_url = source_clean if "://" in source_clean else f"http://{source_clean}"
    try:
        resp = requests.get(
            clean_url,
            headers={"User-Agent": "PhishGuard-WebScanner/1.0"},
            timeout=timeout_sec,
            allow_redirects=True,
            verify=False,
        )
        return resp.text[:MAX_RESPONSE_BYTES]
    except Exception:
        return None


def compare_webpage_content(
    genuine_source: str,
    suspicious_source: str,
    timeout_sec: float = WEB_ANALYSIS_TIMEOUT,
) -> ContentSimilarityResult:
    """Compare backend code / DOM content between genuine and phishing webpages.
    
    Implements NTRO specification:
    Technique (a): 'Backend code / content similarity in web pages.'
    """
    from rapidfuzz import fuzz

    html1 = _get_html(genuine_source, timeout_sec=timeout_sec)
    html2 = _get_html(suspicious_source, timeout_sec=timeout_sec)

    if not html1 or not html2:
        missing = []
        if not html1:
            missing.append(genuine_source)
        if not html2:
            missing.append(suspicious_source)
        return ContentSimilarityResult(
            genuine_target=genuine_source,
            suspicious_target=suspicious_source,
            content_similarity_score=0.0,
            similarity_probability=0.0,
            is_content_lookalike=False,
            verdict="CONTENT UNAVAILABLE (OFFLINE OR UNREACHABLE)",
            dom_similarity=0.0,
            form_similarity=0.0,
            title_similarity=0.0,
            text_similarity=0.0,
            error_message=f"Could not retrieve HTML content for: {', '.join(missing)}",
        )

    try:
        soup1 = BeautifulSoup(html1, "html.parser")
        soup2 = BeautifulSoup(html2, "html.parser")
    except Exception:
        return ContentSimilarityResult(
            genuine_target=genuine_source,
            suspicious_target=suspicious_source,
            content_similarity_score=0.0,
            similarity_probability=0.0,
            is_content_lookalike=False,
            verdict="HTML PARSE ERROR",
            dom_similarity=0.0,
            form_similarity=0.0,
            title_similarity=0.0,
            text_similarity=0.0,
            error_message="Failed to parse webpage HTML structures.",
        )

    # 1. Structural DOM Tag Sequence similarity
    tags1 = " ".join(tag.name for tag in soup1.find_all() if tag.name)
    tags2 = " ".join(tag.name for tag in soup2.find_all() if tag.name)
    dom_sim = fuzz.ratio(tags1, tags2) if tags1 and tags2 else 0.0

    # 2. Form and Input layout similarity (critical for login harvesting pages)
    forms1 = soup1.find_all("form")
    forms2 = soup2.find_all("form")
    inputs1 = sorted(inp.get("type", "text") for inp in soup1.find_all("input"))
    inputs2 = sorted(inp.get("type", "text") for inp in soup2.find_all("input"))

    form_inputs1_str = f"forms:{len(forms1)} inputs:{' '.join(inputs1)}"
    form_inputs2_str = f"forms:{len(forms2)} inputs:{' '.join(inputs2)}"
    form_sim = fuzz.token_sort_ratio(form_inputs1_str, form_inputs2_str)

    # 3. Page Title similarity
    t1 = (soup1.find("title").get_text(strip=True) if soup1.find("title") else "").lower()
    t2 = (soup2.find("title").get_text(strip=True) if soup2.find("title") else "").lower()
    title_sim = fuzz.ratio(t1, t2) if (t1 and t2) else 0.0

    # 4. Visible Text Token similarity
    text1 = soup1.get_text(separator=" ", strip=True).lower()
    text2 = soup2.get_text(separator=" ", strip=True).lower()
    words1 = set(text1.split())
    words2 = set(text2.split())
    if words1 and words2:
        jaccard = len(words1.intersection(words2)) / len(words1.union(words2))
        text_sim = jaccard * 100.0
    else:
        text_sim = 0.0

    # Weighted Composite Backend Code / Content Similarity:
    # 35% DOM structure + 35% Form/Input layout + 15% Title + 15% Text
    composite_score = round(
        (0.35 * dom_sim) + (0.35 * form_sim) + (0.15 * title_sim) + (0.15 * text_sim),
        1,
    )
    sim_prob = round(composite_score / 100.0, 4)

    signals: List[str] = []
    if dom_sim >= 80.0:
        signals.append(f"[CRITICAL] Backend HTML DOM tag structure is virtually cloned ({dom_sim:.1f}%)")
    if form_sim >= 85.0 and len(inputs2) > 0:
        signals.append(f"[CRITICAL] Login / form inputs layout mirrors genuine target ({form_sim:.1f}%)")
    if title_sim >= 90.0 and t1:
        signals.append(f"[HIGH] Webpage title matches genuine site title ('{t2[:40]}')")

    if composite_score >= 80.0:
        verdict = "CRITICAL CODE & CONTENT CLONE (HIGH PHISHING CONFIDENCE)"
        is_lookalike = True
    elif composite_score >= 65.0:
        verdict = "SUSPICIOUS CODE / CONTENT SIMILARITY"
        is_lookalike = True
    elif composite_score >= 45.0:
        verdict = "MODERATE CONTENT OVERLAP"
        is_lookalike = False
    else:
        verdict = "DISTINCT WEB CONTENT (LOW RISK)"
        is_lookalike = False

    return ContentSimilarityResult(
        genuine_target=genuine_source,
        suspicious_target=suspicious_source,
        content_similarity_score=composite_score,
        similarity_probability=sim_prob,
        is_content_lookalike=is_lookalike,
        verdict=verdict,
        dom_similarity=dom_sim,
        form_similarity=form_sim,
        title_similarity=title_sim,
        text_similarity=text_sim,
        signals=signals,
        error_message=None,
    )
