"""WHOIS database analyzer for newly registered domain (NRD) detection.

Implements the open source database (WHOIS Database) requirement of the NTRO specification.
Analyzes domain age, registration timestamp, registrar, and identifies newly registered domains (NRDs)
which represent the primary attack vector for phishing campaigns.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import socket
from typing import Any, List, Optional

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

WHOIS_TIMEOUT_SEC = 3.5  # Strict timeout to keep CLI snappy


@dataclass
class WhoisResult:
    """Structured result of WHOIS database domain analysis."""

    domain: str
    is_available: bool
    creation_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    is_newly_registered: bool = False  # Registered within the last 30 days
    is_young_domain: bool = False  # Registered within the last 90 days
    signals: List[str] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "is_available": self.is_available,
            "creation_date": self.creation_date,
            "domain_age_days": self.domain_age_days,
            "registrar": self.registrar,
            "is_newly_registered": self.is_newly_registered,
            "is_young_domain": self.is_young_domain,
            "signals": self.signals,
            "error_message": self.error_message,
        }


def _parse_creation_date(raw_date: Any) -> Optional[datetime]:
    """Safely parse creation date from diverse WHOIS response formats."""
    if not raw_date:
        return None
    if isinstance(raw_date, list):
        raw_date = raw_date[0]
    if isinstance(raw_date, datetime):
        return raw_date
    if isinstance(raw_date, str):
        for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%d-%b-%Y", "%Y/%m/%d"]:
            try:
                return datetime.strptime(raw_date[:10], fmt[: len(raw_date[:10])])
            except (ValueError, TypeError):
                continue
    return None


def lookup_whois(domain: str, timeout_sec: float = WHOIS_TIMEOUT_SEC) -> WhoisResult:
    """Query WHOIS database to check domain age and registration status.
    
    Resilient and fails safely if offline or if the WHOIS server times out.
    """
    clean_domain = domain.strip().lower()
    if "://" in clean_domain:
        clean_domain = clean_domain.split("://", 1)[1]
    clean_domain = clean_domain.split("/", 1)[0].split(":", 1)[0]

    # Skip IP addresses or local domains
    if clean_domain.replace(".", "").isdigit() or "localhost" in clean_domain:
        return WhoisResult(
            domain=clean_domain,
            is_available=False,
            error_message="Skipped WHOIS query for IP / local host",
        )

    if not HAS_WHOIS:
        return WhoisResult(
            domain=clean_domain,
            is_available=False,
            error_message="python-whois library is not installed",
        )

    original_socket_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_sec)
        w = whois.whois(clean_domain)
    except Exception as exc:
        return WhoisResult(
            domain=clean_domain,
            is_available=False,
            error_message=f"WHOIS lookup failed or timed out: {type(exc).__name__}",
        )
    finally:
        socket.setdefaulttimeout(original_socket_timeout)

    raw_date = getattr(w, "creation_date", None)
    c_date = _parse_creation_date(raw_date)

    registrar = getattr(w, "registrar", None)
    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None

    domain_age_days: Optional[int] = None
    is_newly_registered = False
    is_young_domain = False
    signals: List[str] = []

    if c_date:
        # Make timezone-naive or UTC for calculation
        if c_date.tzinfo is not None:
            c_date_utc = c_date.astimezone(timezone.utc).replace(tzinfo=None)
        else:
            c_date_utc = c_date
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        diff = now_utc - c_date_utc
        domain_age_days = max(0, diff.days)

        if domain_age_days <= 30:
            is_newly_registered = True
            is_young_domain = True
            signals.append(
                f"[CRITICAL] Newly Registered Domain (NRD): Registered {domain_age_days} days ago (<30 days threshold)"
            )
        elif domain_age_days <= 90:
            is_young_domain = True
            signals.append(
                f"[HIGH] Young Domain: Registered {domain_age_days} days ago (<90 days threshold)"
            )
        else:
            signals.append(f"[INFO] Domain is established ({domain_age_days} days old)")
    else:
        signals.append("[LOW] Domain creation date is omitted or masked in WHOIS records")

    return WhoisResult(
        domain=clean_domain,
        is_available=True,
        creation_date=c_date.strftime("%Y-%m-%d") if c_date else None,
        domain_age_days=domain_age_days,
        registrar=str(registrar) if registrar else None,
        is_newly_registered=is_newly_registered,
        is_young_domain=is_young_domain,
        signals=signals,
        error_message=None,
    )
