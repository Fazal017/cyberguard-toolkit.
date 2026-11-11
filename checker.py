import socket
import ssl
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse


SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS connections.",
    "Content-Security-Policy": "Helps limit the sources from which content can load.",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing.",
    "Referrer-Policy": "Controls how much referrer information is shared.",
    "Permissions-Policy": "Controls access to selected browser features.",
    "X-Frame-Options": "Helps control whether the page can be embedded in frames.",
}


def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")
    return parsed


def check_headers(url):
    request = Request(url, headers={"User-Agent": "CyberGuard-Toolkit/0.1"})
    try:
        with urlopen(request, timeout=10) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
    except (URLError, TimeoutError, OSError) as exc:
        return {"error": str(exc), "checks": []}

    checks = []
    for header, note in SECURITY_HEADERS.items():
        checks.append({
            "header": header,
            "present": header.lower() in headers,
            "note": note,
        })
    return {"error": None, "checks": checks}


def check_tls(hostname, port=443):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
        expiry = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return {
            "error": None,
            "expires_at": expiry.isoformat(),
            "days_remaining": (expiry - now).days,
        }
    except (OSError, ssl.SSLError, KeyError, ValueError) as exc:
        return {"error": str(exc), "expires_at": None, "days_remaining": None}


def check_dns(hostname):
    try:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        addresses = sorted({item[4][0] for item in results})
        return {"error": None, "addresses": addresses}
    except OSError as exc:
        return {"error": str(exc), "addresses": []}


def check_site(url):
    parsed = validate_url(url)
    normalized_url = url.rstrip("/")
    headers_result = check_headers(normalized_url)
    if headers_result["error"]:
        header_checks = [{
            "header": "HTTP request",
            "present": False,
            "note": headers_result["error"],
        }]
    else:
        header_checks = headers_result["checks"]

    tls_result = (
        check_tls(parsed.hostname, parsed.port or 443)
        if parsed.scheme == "https"
        else {"error": "The supplied URL uses HTTP, not HTTPS.",
              "expires_at": None, "days_remaining": None}
    )

    return {
        "tool": "CyberGuard Toolkit",
        "version": "0.1.0",
        "url": normalized_url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "http_headers": header_checks,
        "tls": tls_result,
        "dns": check_dns(parsed.hostname),
        "disclaimer": "Basic defensive checks only; not a full security audit.",
    }
