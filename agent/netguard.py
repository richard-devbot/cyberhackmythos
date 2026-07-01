"""Network egress guard for the ``fetch_webpage`` tool.

Without this, ``fetch_webpage`` is a Server-Side Request Forgery primitive: the
LLM (steered by untrusted code or web content) can point it at internal services
or the cloud metadata endpoint (``169.254.169.254``) and read back the response.

The guard resolves every hostname and refuses any request that resolves to a
private, loopback, link-local, or otherwise non-public address. Redirects are
followed manually so each hop is re-validated (a naive ``allow_redirects=True``
would let a public URL 302 you straight into the metadata endpoint).

Known limitation (documented, accepted for Phase 0): a DNS-rebinding attacker can
change the record between our resolution check and the socket connect (TOCTOU).
Fully closing that requires pinning the validated IP into the connection, which
is a Phase 1 hardening item.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import requests

from . import config


class UrlNotAllowed(ValueError):
    """Raised when a URL fails SSRF validation."""


def _ip_is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    # Reject everything that isn't a normal, globally-routable address.
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local          # covers 169.254.0.0/16 metadata + fe80::/10
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return False
    # 100.64.0.0/10 (CGNAT) is not flagged private by ipaddress; block it too.
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


def _resolve_all(host: str) -> list[str]:
    """Return every IP a host resolves to (v4 and v6)."""
    infos = socket.getaddrinfo(host, None)
    return list({info[4][0] for info in infos})


def validate_public_url(url: str) -> None:
    """Raise :class:`UrlNotAllowed` unless *url* is safe to fetch.

    Checks scheme, that a host is present, and that **all** resolved IPs are
    public. Bypassed only when ``CYBERHACKMYTHOS_FETCH_ALLOW_PRIVATE`` is set.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in config.FETCH_ALLOWED_SCHEMES:
        raise UrlNotAllowed(
            f"scheme '{scheme}' not allowed (allowed: {config.FETCH_ALLOWED_SCHEMES})"
        )
    host = parsed.hostname
    if not host:
        raise UrlNotAllowed("URL has no host")

    if config.FETCH_ALLOW_PRIVATE:
        return

    try:
        ips = _resolve_all(host)
    except socket.gaierror as exc:
        raise UrlNotAllowed(f"could not resolve host '{host}': {exc}") from exc
    if not ips:
        raise UrlNotAllowed(f"host '{host}' resolved to no addresses")
    for ip in ips:
        if not _ip_is_public(ip):
            raise UrlNotAllowed(
                f"host '{host}' resolves to non-public address {ip} (blocked)"
            )


def safe_fetch(url: str) -> str:
    """Fetch *url* with SSRF validation, size cap, and per-hop redirect checks.

    Returns the decoded body text. Raises :class:`UrlNotAllowed` for blocked
    URLs and ``requests.RequestException`` for transport errors.
    """
    current = url
    for _ in range(config.FETCH_MAX_REDIRECTS + 1):
        validate_public_url(current)
        resp = requests.get(
            current,
            timeout=config.FETCH_TIMEOUT_SECONDS,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "cyberhackmythos/0.1 (+security-scanner)"},
        )
        # Manual redirect handling so the destination is re-validated.
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            resp.close()
            if not location:
                raise requests.TooManyRedirects("redirect without Location header")
            current = requests.compat.urljoin(current, location)
            continue

        resp.raise_for_status()
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > config.FETCH_MAX_BYTES:
                resp.close()
                chunks.append(chunk)
                break
            chunks.append(chunk)
        resp.close()
        body = b"".join(chunks)[: config.FETCH_MAX_BYTES]
        return body.decode(resp.encoding or "utf-8", errors="replace")

    raise requests.TooManyRedirects(
        f"exceeded {config.FETCH_MAX_REDIRECTS} redirects starting from {url}"
    )
