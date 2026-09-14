"""Utility functions for URL/domain normalization and input validation."""

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import tldextract


@dataclass
class TargetInfo:
    """Structured representation of a parsed and validated target."""

    original_input: str
    normalized_url: str
    hostname: str
    domain: str
    registered_domain: str
    subdomain: str
    path: str
    is_ip: bool
    is_valid: bool
    error_message: Optional[str] = None


# Basic regex for valid domain labels (RFC 1035 / RFC 1123 compliant subset)
DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


def is_ip_address(host: str) -> bool:
    """Check whether a given host string is a valid IPv4 or IPv6 address."""
    if not host:
        return False
    # Strip optional enclosing brackets for IPv6
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def normalize_target(raw_input: str) -> TargetInfo:
    """Normalize and validate user input into structured TargetInfo.

    Handles bare domains (example.com), URLs (https://example.com/path),
    IP-address hosts (http://192.168.1.1), and strips whitespace.
    """
    if not raw_input or not raw_input.strip():
        return TargetInfo(
            original_input=raw_input or "",
            normalized_url="",
            hostname="",
            domain="",
            registered_domain="",
            subdomain="",
            path="",
            is_ip=False,
            is_valid=False,
            error_message="Target input cannot be empty.",
        )

    cleaned = raw_input.strip()

    # Reject obvious invalid characters such as whitespace or @ inside host
    if " " in cleaned:
        return TargetInfo(
            original_input=cleaned,
            normalized_url="",
            hostname="",
            domain="",
            registered_domain="",
            subdomain="",
            path="",
            is_ip=False,
            is_valid=False,
            error_message="Invalid target: contains spaces.",
        )

    # Ensure URL scheme exists for urllib.parse to reliably extract netloc
    if "://" not in cleaned:
        url_to_parse = f"http://{cleaned}"
    else:
        url_to_parse = cleaned

    try:
        parsed = urlparse(url_to_parse)
    except Exception as exc:
        return TargetInfo(
            original_input=cleaned,
            normalized_url="",
            hostname="",
            domain="",
            registered_domain="",
            subdomain="",
            path="",
            is_ip=False,
            is_valid=False,
            error_message=f"Malformed URL structure: {exc}",
        )

    netloc = parsed.netloc.lower()

    # Reject userinfo (@) syntax in hostname (often used in phishing tricks e.g. legitimate.com@phish.com)
    if "@" in netloc:
        return TargetInfo(
            original_input=cleaned,
            normalized_url="",
            hostname="",
            domain="",
            registered_domain="",
            subdomain="",
            path="",
            is_ip=False,
            is_valid=False,
            error_message="Target contains '@' credentials syntax, which is invalid or suspicious.",
        )

    # Strip port if present
    if ":" in netloc:
        hostname = netloc.split(":")[0]
    else:
        hostname = netloc

    if not hostname:
        return TargetInfo(
            original_input=cleaned,
            normalized_url="",
            hostname="",
            domain="",
            registered_domain="",
            subdomain="",
            path="",
            is_ip=False,
            is_valid=False,
            error_message="Could not extract a valid hostname from the input.",
        )

    # Check if host is an IP address
    if is_ip_address(hostname):
        return TargetInfo(
            original_input=cleaned,
            normalized_url=url_to_parse,
            hostname=hostname,
            domain=hostname,
            registered_domain=hostname,
            subdomain="",
            path=parsed.path or "/",
            is_ip=True,
            is_valid=True,
            error_message=None,
        )

    # Extract domain, subdomain, and suffix using tldextract
    extracted = tldextract.extract(hostname)
    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain
    # Support modern tldextract top_domain_under_public_suffix without triggering deprecated property
    if hasattr(extracted, "top_domain_under_public_suffix"):
        registered_domain = extracted.top_domain_under_public_suffix
    elif hasattr(extracted, "registered_domain"):
        registered_domain = extracted.registered_domain
    else:
        registered_domain = f"{domain}.{suffix}" if suffix else domain

    # Validate each label in domain
    labels = hostname.split(".")
    if len(labels) < 2 or not suffix:
        return TargetInfo(
            original_input=cleaned,
            normalized_url="",
            hostname=hostname,
            domain=domain,
            registered_domain=registered_domain,
            subdomain=subdomain,
            path=parsed.path or "/",
            is_ip=False,
            is_valid=False,
            error_message=f"Invalid domain '{hostname}': missing valid top-level domain (TLD).",
        )

    for label in labels:
        if not label:
            return TargetInfo(
                original_input=cleaned,
                normalized_url="",
                hostname=hostname,
                domain=domain,
                registered_domain=registered_domain,
                subdomain=subdomain,
                path=parsed.path or "/",
                is_ip=False,
                is_valid=False,
                error_message=f"Invalid domain '{hostname}': contains consecutive dots or empty label.",
            )
        if not DOMAIN_LABEL_REGEX.match(label):
            return TargetInfo(
                original_input=cleaned,
                normalized_url="",
                hostname=hostname,
                domain=domain,
                registered_domain=registered_domain,
                subdomain=subdomain,
                path=parsed.path or "/",
                is_ip=False,
                is_valid=False,
                error_message=f"Invalid label '{label}' in domain '{hostname}'.",
            )

    return TargetInfo(
        original_input=cleaned,
        normalized_url=url_to_parse,
        hostname=hostname,
        domain=domain,
        registered_domain=registered_domain,
        subdomain=subdomain,
        path=parsed.path or "/",
        is_ip=False,
        is_valid=True,
        error_message=None,
    )


def validate_target(raw_input: str) -> TargetInfo:
    """Validate a target and raise a clear ValueError if invalid."""
    info = normalize_target(raw_input)
    if not info.is_valid:
        raise ValueError(info.error_message or f"Invalid target: '{raw_input}'")
    return info
