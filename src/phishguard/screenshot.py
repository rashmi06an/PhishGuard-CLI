"""Automated webpage screenshot capture for PhishGuard-CLI.

Implements the capture half of NTRO Technique (b): instead of requiring the user
to supply screenshots manually, this module renders a live webpage to a PNG so the
genuine and suspicious sites can be screenshotted and compared automatically.

Rendering a real page requires a browser engine, so Playwright is used as an
OPTIONAL dependency. If Playwright (or its browser binary) is unavailable, the
function fails safely and returns an actionable install hint rather than crashing.
"""

import os
from dataclasses import dataclass
from typing import Optional

PLAYWRIGHT_INSTALL_HINT = (
    "Automated capture needs Playwright. Install it once with:\n"
    "    pip install playwright\n"
    "    playwright install chromium"
)


@dataclass
class CaptureResult:
    """Result of an automated screenshot capture attempt."""

    url: str
    output_path: Optional[str]
    success: bool
    error_message: Optional[str] = None


def capture_screenshot(
    url: str,
    output_path: str,
    timeout_ms: int = 15000,
    width: int = 1280,
    height: int = 800,
) -> CaptureResult:
    """Render a live webpage to a PNG screenshot using headless Chromium.

    Fails safely (success=False) if Playwright is missing, the browser is not
    installed, or the page is unreachable.
    """
    clean_url = url if "://" in url else f"https://{url}"

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return CaptureResult(
            url=clean_url,
            output_path=None,
            success=False,
            error_message=f"Playwright not installed.\n{PLAYWRIGHT_INSTALL_HINT}",
        )

    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": width, "height": height})
                page.goto(clean_url, timeout=timeout_ms, wait_until="load")
                page.screenshot(path=output_path, full_page=False)
            finally:
                browser.close()
    except Exception as exc:
        msg = str(exc)
        if "Executable doesn't exist" in msg or "playwright install" in msg:
            return CaptureResult(
                url=clean_url,
                output_path=None,
                success=False,
                error_message=f"Chromium browser not installed.\n{PLAYWRIGHT_INSTALL_HINT}",
            )
        return CaptureResult(
            url=clean_url,
            output_path=None,
            success=False,
            error_message=f"Capture failed for '{clean_url}': {type(exc).__name__}: {exc}",
        )

    return CaptureResult(url=clean_url, output_path=output_path, success=True)
