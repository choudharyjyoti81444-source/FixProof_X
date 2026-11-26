
import requests
import socket
import ipaddress

from urllib.parse import urlparse
from risk_engine import calculate_risk, get_risk_summary
from technology_detector import detect_technologies


SECURITY_HEADERS = {
    "Content Security Policy": {
        "header": "Content-Security-Policy",
        "guidance": "Configure a suitable Content-Security-Policy header.",
        "severity": "High"
    },
    "Clickjacking Protection": {
        "header": "X-Frame-Options",
        "guidance": "Configure X-Frame-Options or CSP frame-ancestors.",
        "severity": "Medium"
    },
    "HSTS Security": {
        "header": "Strict-Transport-Security",
        "guidance": "Configure Strict-Transport-Security on HTTPS.",
        "severity": "Medium"
    },
    "MIME Sniffing Protection": {
        "header": "X-Content-Type-Options",
        "guidance": "Set X-Content-Type-Options: nosniff.",
        "severity": "Medium"
    },
    "Referrer Policy": {
        "header": "Referrer-Policy",
        "guidance": "Configure a suitable Referrer-Policy.",
        "severity": "Low"
    },
    "Permissions Policy": {
        "header": "Permissions-Policy",
        "guidance": "Review and configure Permissions-Policy.",
        "severity": "Low"
    },
    "Cross-Origin Opener Policy": {
        "header": "Cross-Origin-Opener-Policy",
        "guidance": "Review whether Cross-Origin-Opener-Policy is appropriate.",
        "severity": "Low"
    },
    "Cross-Origin Resource Policy": {
        "header": "Cross-Origin-Resource-Policy",
        "guidance": "Review whether Cross-Origin-Resource-Policy is appropriate.",
        "severity": "Low"
    }
}


def validate_website_url(url):

    url = url.strip()

    if not url:
        raise ValueError("Please enter a website URL.")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS websites are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid website URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing login credentials are not allowed.")

    if parsed.fragment:
        url = url.split("#", 1)[0]
        parsed = urlparse(url)

    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Invalid website port.") from error

    allowed_port = 443 if parsed.scheme == "https" else 80

    if port is not None and port != allowed_port:
        raise ValueError("Only standard HTTP and HTTPS ports are allowed.")

    hostname = parsed.hostname

    try:
        addresses = socket.getaddrinfo(
            hostname,
            allowed_port,
            type=socket.SOCK_STREAM
        )

        ips = {item[4][0] for item in addresses}

        if not ips:
            raise ValueError("Website address could not be resolved.")

        for address in ips:
            ip = ipaddress.ip_address(address)

            if not ip.is_global:
                raise ValueError("Only public websites can be scanned.")

    except socket.gaierror as error:
        raise ValueError(
            "Website address could not be resolved."
        ) from error

    return url, parsed


def create_check(name, status, details, guidance, severity="Medium"):

    return {
        "name": name,
        "status": status,
        "details": details,
        "guidance": guidance,
        "severity": severity
    }


def check_cookie_security(response):

    cookie_headers = []

    try:
        cookie_headers = response.raw.headers.getlist("Set-Cookie")

    except (AttributeError, TypeError):

        cookie_header = response.headers.get("Set-Cookie")

        if cookie_header:
            cookie_headers = [cookie_header]

    if not cookie_headers:

        return create_check(
            "Cookie Security",
            "Not Observed",
            "No Set-Cookie header was observed in this response.",
            "Review cookie security if the application uses session cookies.",
            "Low"
        )

    insecure_cookies = []

    for cookie in cookie_headers:

        attributes = [
            part.strip().split("=", 1)[0].lower()
            for part in cookie.split(";")
        ]

        missing_flags = []

        if "secure" not in attributes:
            missing_flags.append("Secure")

        if "httponly" not in attributes:
            missing_flags.append("HttpOnly")

        if "samesite" not in attributes:
            missing_flags.append("SameSite")

        if missing_flags:
            insecure_cookies.append(", ".join(missing_flags))

    if insecure_cookies:

        return create_check(
            "Cookie Security",
            "Missing",
            "One or more observed cookies may be missing recommended security attributes.",
            "Review Secure, HttpOnly and SameSite attributes for applicable cookies.",
            "Medium"
        )

    return create_check(
        "Cookie Security",
        "Passed",
        "Observed cookies contain Secure, HttpOnly and SameSite attributes.",
        "Continue reviewing cookie configuration.",
        "Low"
    )


def scan_website(url):

    url, parsed = validate_website_url(url)

    response = None

    try:

        response = requests.get(
            url,
            timeout=(5, 10),
            allow_redirects=False,
            stream=True,
            verify=True,
            headers={
                "User-Agent": "FixProofX-Security-Checker/2.0"
            }
        )

        headers = response.headers
        status_code = response.status_code
        is_https = parsed.scheme == "https"

        checks = []

        # 1. HTTPS Encryption

        checks.append(
            create_check(
                "HTTPS Encryption",
                "Passed" if is_https else "Failed",
                (
                    "Website uses HTTPS."
                    if is_https
                    else "Website uses HTTP instead of HTTPS."
                ),
                (
                    "Continue using HTTPS."
                    if is_https
                    else "Configure HTTPS with a valid TLS certificate."
                ),
                "High"
            )
        )

        # 2. Content Security Policy

        csp = headers.get("Content-Security-Policy", "")

        checks.append(
            create_check(
                "Content Security Policy",
                "Passed" if csp else "Missing",
                (
                    "CSP header detected."
                    if csp
                    else "CSP header was not detected."
                ),
                (
                    "Review your CSP policy regularly."
                    if csp
                    else SECURITY_HEADERS["Content Security Policy"]["guidance"]
                ),
                "High"
            )
        )

        # 3. Clickjacking Protection

        x_frame = headers.get("X-Frame-Options", "")
        frame_ancestors = "frame-ancestors" in csp.lower()
        clickjacking = bool(x_frame or frame_ancestors)

        checks.append(
            create_check(
                "Clickjacking Protection",
                "Passed" if clickjacking else "Missing",
                (
                    "Frame protection detected."
                    if clickjacking
                    else "Frame protection was not detected."
                ),
                (
                    "Review your frame protection policy."
                    if clickjacking
                    else SECURITY_HEADERS["Clickjacking Protection"]["guidance"]
                ),
                "Medium"
            )
        )

        # 4. HSTS Security

        hsts = headers.get("Strict-Transport-Security", "")
        hsts_present = bool(hsts and is_https)

        checks.append(
            create_check(
                "HSTS Security",
                "Passed" if hsts_present else "Missing",
                (
                    "HSTS header detected."
                    if hsts_present
                    else "HSTS header was not detected on the HTTPS response."
                ),
                (
                    "Review your HSTS policy."
                    if hsts_present
                    else SECURITY_HEADERS["HSTS Security"]["guidance"]
                ),
                "Medium"
            )
        )

        # 5. MIME Sniffing Protection

        nosniff = (
            headers.get("X-Content-Type-Options", "").lower() == "nosniff"
        )

        checks.append(
            create_check(
                "MIME Sniffing Protection",
                "Passed" if nosniff else "Missing",
                (
                    "nosniff protection detected."
                    if nosniff
                    else "nosniff protection was not detected."
                ),
                (
                    "Keep nosniff protection enabled."
                    if nosniff
                    else SECURITY_HEADERS["MIME Sniffing Protection"]["guidance"]
                ),
                "Medium"
            )
        )

        # 6. Referrer Policy

        referrer = headers.get("Referrer-Policy", "")

        checks.append(
            create_check(
                "Referrer Policy",
                "Passed" if referrer else "Missing",
                (
                    "Referrer-Policy header detected."
                    if referrer
                    else "Referrer-Policy header was not detected."
                ),
                (
                    "Review your Referrer-Policy."
                    if referrer
                    else SECURITY_HEADERS["Referrer Policy"]["guidance"]
                ),
                "Low"
            )
        )

        # 7. Permissions Policy

        permissions = headers.get("Permissions-Policy", "")

        checks.append(
            create_check(
                "Permissions Policy",
                "Passed" if permissions else "Missing",
                (
                    "Permissions-Policy header detected."
                    if permissions
                    else "Permissions-Policy header was not detected."
                ),
                (
                    "Review your Permissions-Policy."
                    if permissions
                    else SECURITY_HEADERS["Permissions Policy"]["guidance"]
                ),
                "Low"
            )
        )

        # 8. Cross-Origin Opener Policy

        coop = headers.get("Cross-Origin-Opener-Policy", "")

        checks.append(
            create_check(
                "Cross-Origin Opener Policy",
                "Passed" if coop else "Missing",
                (
                    "Cross-Origin-Opener-Policy header detected."
                    if coop
                    else "Cross-Origin-Opener-Policy header was not detected."
                ),
                (
                    "Review your cross-origin opener policy."
                    if coop
                    else SECURITY_HEADERS["Cross-Origin Opener Policy"]["guidance"]
                ),
                "Low"
            )
        )

        # 9. Cross-Origin Resource Policy

        corp = headers.get("Cross-Origin-Resource-Policy", "")

        checks.append(
            create_check(
                "Cross-Origin Resource Policy",
                "Passed" if corp else "Missing",
                (
                    "Cross-Origin-Resource-Policy header detected."
                    if corp
                    else "Cross-Origin-Resource-Policy header was not detected."
                ),
                (
                    "Review your cross-origin resource policy."
                    if corp
                    else SECURITY_HEADERS["Cross-Origin Resource Policy"]["guidance"]
                ),
                "Low"
            )
        )

        # 10. Cookie Security

        checks.append(check_cookie_security(response))

        # Smart Risk Engine

        score, risk_level = calculate_risk(checks)
        risk_summary = get_risk_summary(checks)

        # Technology Detection

        technologies = detect_technologies(headers)

        return {
            "url": url,
            "score": score,
            "risk_level": risk_level,
            "results": checks,
            "risk_summary": risk_summary,
            "technologies": technologies,
            "http_status": status_code
        }

    except requests.exceptions.Timeout as error:

        raise ValueError(
            "Website request timed out. Please try again."
        ) from error

    except requests.exceptions.SSLError as error:

        raise ValueError(
            "Website TLS certificate verification failed."
        ) from error

    except requests.RequestException as error:

        raise ValueError(
            "Website request failed. Check the URL and try again."
        ) from error

    finally:

        if response is not None:
            response.close()
