"""Newly Registered Domain (NRD) feed ingestion for PhishGuard-CLI.

Implements the NTRO premise that the tool should ingest lists of newly registered
domains from open-source databases automatically. Supports three source types:

  1. Local file  - a .txt (one domain per line) or .csv (with a domain/url column)
  2. Plain URL   - a remote text feed of newly registered domains
  3. Zip URL     - a .zip archive (e.g. whoisds.com daily NRD list) whose first
                   text member is a newline-separated list of domains

All loaders fail safely and return a de-duplicated, cleaned list of domains.
"""

import csv
import io
import os
import zipfile
from typing import List, Optional

_COMMENT_PREFIXES = ("#", "//")
_DOMAIN_COLUMNS = ("domain", "url", "target", "hostname")


def _clean_domain(raw: str) -> Optional[str]:
    """Normalize a single feed line into a bare domain, or None if unusable."""
    if raw is None:
        return None
    d = raw.strip().strip('",').lower()
    if not d or d.startswith(_COMMENT_PREFIXES):
        return None
    # Strip scheme and any path/port so feeds containing full URLs still work
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    return d or None


def _dedupe_preserve_order(domains: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for d in domains:
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _parse_text_feed(text: str) -> List[str]:
    """Parse a newline-separated text feed into cleaned domains."""
    domains = [_clean_domain(line) for line in text.splitlines()]
    return _dedupe_preserve_order([d for d in domains if d])


def _parse_csv_feed(text: str) -> List[str]:
    """Parse a CSV feed, auto-detecting the domain/url column."""
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames:
        col = None
        for name in reader.fieldnames:
            if name and name.strip().lower() in _DOMAIN_COLUMNS:
                col = name
                break
        if col:
            domains = [_clean_domain(str(row.get(col, ""))) for row in reader]
            return _dedupe_preserve_order([d for d in domains if d])
    # Fallback: treat as a plain one-domain-per-line text feed
    return _parse_text_feed(text)


def _read_zip_bytes(blob: bytes) -> List[str]:
    """Extract the first text member of a zip archive and parse it as a feed."""
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        members = [n for n in zf.namelist() if not n.endswith("/")]
        if not members:
            return []
        with zf.open(members[0]) as fh:
            text = fh.read().decode("utf-8", errors="ignore")
    return _parse_text_feed(text)


def load_nrd_feed(source: str, timeout_sec: float = 10.0, limit: Optional[int] = None) -> List[str]:
    """Load a list of newly registered domains from a file, URL, or zip URL.

    Raises:
        FileNotFoundError: if a local path is given but does not exist.
        ValueError: if a remote feed cannot be retrieved or parsed.
    """
    source = source.strip()

    # 1. Remote source (http/https)
    if source.lower().startswith(("http://", "https://")):
        try:
            import requests  # imported lazily so file-based feeds need no network stack

            resp = requests.get(
                source,
                headers={"User-Agent": "PhishGuard-NRD-Feed/1.0"},
                timeout=timeout_sec,
            )
            resp.raise_for_status()
            content = resp.content
            resp.close()
        except Exception as exc:
            raise ValueError(f"Could not retrieve NRD feed '{source}': {type(exc).__name__}: {exc}")

        if source.lower().endswith(".zip") or content[:2] == b"PK":
            domains = _read_zip_bytes(content)
        else:
            text = content.decode("utf-8", errors="ignore")
            domains = _parse_csv_feed(text) if source.lower().endswith(".csv") else _parse_text_feed(text)

    # 2. Local file source
    else:
        if not os.path.isfile(source):
            raise FileNotFoundError(f"NRD feed file not found: '{source}'")
        if source.lower().endswith(".zip"):
            with open(source, "rb") as fh:
                domains = _read_zip_bytes(fh.read())
        else:
            with open(source, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
            domains = _parse_csv_feed(text) if source.lower().endswith(".csv") else _parse_text_feed(text)

    if limit is not None and limit > 0:
        domains = domains[:limit]
    return domains
