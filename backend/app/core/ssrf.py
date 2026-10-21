"""Server-Side Request Forgery (SSRF) and DNS-rebinding protection module.

Ensures that target URLs extracted from emails, messages, or user inputs
cannot target internal infrastructure, loopback interfaces, private RFC 1918 networks,
link-local endpoints, or cloud metadata services (e.g., AWS/GCP 169.254.169.254).
"""
import ipaddress
import logging
import socket
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("rise_phish.ssrf")

ALLOWED_SCHEMES: Set[str] = {"http", "https"}

# Cloud metadata addresses and hostnames
CLOUD_METADATA_IPS: Set[str] = {
    "169.254.169.254",  # AWS EC2, GCP, Azure metadata
    "fd00:ec2::254",     # AWS IPv6 metadata
}

CLOUD_METADATA_HOSTS: Set[str] = {
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

# Maximum allowed URL length to prevent buffer and memory exhaustion
MAX_URL_LENGTH = 4096


def validate_url_syntax(url: str) -> Tuple[bool, Optional[str]]:
    """Validates basic syntax, scheme, and presence of hostname.

    Returns:
        (is_valid, error_reason)
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string."

    if len(url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum length of {MAX_URL_LENGTH} characters."

    parsed = urlparse(url.strip())

    if not parsed.scheme:
        return False, f"Missing scheme in URL '{url}'."

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"Disallowed scheme '{parsed.scheme}'. Only http and https are permitted."

    if not parsed.netloc:
        return False, f"Malformed URL '{url}': Missing netloc/hostname."

    hostname = parsed.hostname
    if not hostname:
        return False, f"Malformed URL '{url}': Unable to parse hostname."

    # Check for forbidden metadata hostnames
    if hostname.lower() in CLOUD_METADATA_HOSTS:
        return False, f"Access to cloud metadata host '{hostname}' is strictly prohibited."

    return True, None


def resolve_and_verify_ip(
    hostname: str,
    port: int,
    allow_loopback: bool = False,
    allow_private: bool = False,
) -> Tuple[bool, Optional[str], List[str]]:
    """Performs DNS resolution and verifies that all resolved IPs are safe public addresses.

    Args:
        hostname: Domain or IP string to resolve.
        port: Destination port number.
        allow_loopback: If True, permits loopback (e.g. for synthetic local testing).
        allow_private: If True, permits RFC 1918 private IPs (for testing only).

    Returns:
        (is_safe, error_reason, resolved_ip_list)
    """
    resolved_ips: List[str] = []

    try:
        # Resolve all addresses (both IPv4 and IPv6)
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as dns_err:
        return False, f"DNS resolution failed for hostname '{hostname}': {dns_err}", []
    except Exception as exc:
        return False, f"Unexpected error during DNS resolution for '{hostname}': {exc}", []

    for item in addr_info:
        sockaddr = item[4]
        ip_str = sockaddr[0]
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    if not resolved_ips:
        return False, f"No IP addresses could be resolved for '{hostname}'.", []

    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid resolved IP address string: '{ip_str}'", resolved_ips

        # 1. Cloud metadata check
        if ip_str in CLOUD_METADATA_IPS:
            return False, f"Resolved IP '{ip_str}' belongs to cloud metadata service.", resolved_ips

        # 2. Loopback check (127.0.0.0/8, ::1)
        if ip_obj.is_loopback:
            if not allow_loopback:
                return False, f"Resolved IP '{ip_str}' is a loopback address (SSRF blocked).", resolved_ips

        # 3. Private network check (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
        if ip_obj.is_private:
            if not allow_private and not (allow_loopback and ip_obj.is_loopback):
                return False, f"Resolved IP '{ip_str}' is a private network address (RFC 1918 blocked).", resolved_ips

        # 4. Link-local check (169.254.0.0/16, fe80::/10)
        if ip_obj.is_link_local:
            return False, f"Resolved IP '{ip_str}' is a link-local address (blocked).", resolved_ips

        # 5. Multicast or Reserved
        if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return False, f"Resolved IP '{ip_str}' is multicast, reserved, or unspecified.", resolved_ips

    return True, None, resolved_ips


def is_ssrf_safe(
    url: str,
    allow_loopback: bool = False,
    allow_private: bool = False,
) -> Tuple[bool, Optional[str], List[str]]:
    """Complete SSRF safety check validating URL syntax, DNS resolution, and destination IPs.

    Args:
        url: Webpage URL to evaluate.
        allow_loopback: Permit loopback resolution (for local synthetic tests).
        allow_private: Permit private subnets.

    Returns:
        (is_safe, error_reason, resolved_ips)
    """
    valid, syntax_err = validate_url_syntax(url)
    if not valid:
        return False, syntax_err, []

    parsed = urlparse(url.strip())
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

    # Validate port bounds
    if port < 1 or port > 65535:
        return False, f"Invalid destination port '{port}'.", []

    return resolve_and_verify_ip(
        hostname=hostname,
        port=port,
        allow_loopback=allow_loopback,
        allow_private=allow_private,
    )
