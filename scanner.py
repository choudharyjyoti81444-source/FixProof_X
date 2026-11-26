
import ipaddress
import socket
from urllib.parse import urlparse

import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": "CSP",
    "Strict-Transport-Security": "HSTS",
    "X-Frame-Options": "X-Frame-Options",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "Referrer-Policy": "Referrer Policy"
}


def validate_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("Please enter a website URL.")

    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS websites are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid website URL.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing login credentials are not allowed.")

    if parsed.port not in (None, 80, 443):
        raise ValueError("Only standard web ports are supported.")

    hostname = parsed.hostname.lower()

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Localhost scanning is not supported.")

    try:
        addresses = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise ValueError("Website hostname could not be resolved.")

    if not addresses:
        raise ValueError("Website IP address could not be resolved.")

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])

        if not ip.is_global:
            raise ValueError("Only public websites can be scanned.")

    return raw_url


def scan_website(raw_url):
    url = validate_url(raw_url)

    try:
        response = requests.get(
            url,
            timeout=12,
            allow_redirects=True,
            headers={
                "User-Agent": "FixProofX-Security-Scanner/1.0"
            },
            stream=True
        )

    except requests.exceptions.SSLError:
        raise ValueError("SSL certificate verification failed.")

    except requests.exceptions.Timeout:
        raise ValueError("Website response timed out.")

    except requests.exceptions.RequestException:
        raise ValueError("Could not connect to the website.")

    try:
        final_url = response.url
        parsed_final = urlparse(final_url)

        if parsed_final.scheme != "https":
            if parsed_final.scheme != "http":
                raise ValueError("Website redirected to an unsupported URL.")

            final_url = validate_url(final_url)

        headers = response.headers
        results = []
        passed = 0

        def add_result(name, status, details):
            nonlocal passed

            if status == "Passed":
                passed += 1

            results.append({
                "name": name,
                "status": status,
                "details": details
            })

        if parsed_final.scheme == "https":
            add_result(
                "HTTPS",
                "Passed",
                "Website uses HTTPS."
            )
        else:
            add_result(
                "HTTPS",
                "Failed",
                "Website is using HTTP instead of HTTPS."
            )

        for header, label in SECURITY_HEADERS.items():
            if headers.get(header):
                add_result(
                    label,
                    "Passed",
                    "Security header is present."
                )
            else:
                add_result(
                    label,
                    "Failed",
                    "Security header is missing."
                )

        cookie_headers = response.raw.headers.getlist("Set-Cookie")

        if not cookie_headers:
            add_result(
                "Cookie Security",
                "Passed",
                "No cookies were set in this response."
            )
        else:
            insecure_cookies = []

            for cookie in cookie_headers:
                lower_cookie = cookie.lower()

                if "secure" not in lower_cookie:
                    insecure_cookies.append("Secure")

                if "httponly" not in lower_cookie:
                    insecure_cookies.append("HttpOnly")

            if not insecure_cookies:
                add_result(
                    "Cookie Security",
                    "Passed",
                    "Observed cookies include Secure and HttpOnly flags."
                )
            else:
                missing = ", ".join(sorted(set(insecure_cookies)))

                add_result(
                    "Cookie Security",
                    "Failed",
                    "Some observed cookies may be missing: " + missing
                )

        total = len(results)
        score = round((passed / total) * 100) if total else 0

        if score >= 80:
            risk_level = "Low"
        elif score >= 50:
            risk_level = "Medium"
        else:
            risk_level = "High"

        technology = []

        server = headers.get("Server")
        powered_by = headers.get("X-Powered-By")

        if server:
            technology.append("Server: " + server)

        if powered_by:
            technology.append("Technology: " + powered_by)

        if not technology:
            technology.append("Technology details not publicly disclosed.")

        return {
            "url": final_url,
            "score": score,
            "risk_level": risk_level,
            "results": results,
            "technology": technology,
            "http_status": response.status_code,
            "total_checks": total,
            "passed_checks": passed
        }

    finally:
        response.close()
