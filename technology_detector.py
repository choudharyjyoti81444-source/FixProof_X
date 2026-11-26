
def detect_technologies(headers):
    """
    Detect possible website technologies using HTTP response headers.
    This is passive detection, not a vulnerability test.
    """

    technologies = []

    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")

    if server:
        technologies.append({
            "name": server,
            "category": "Web Server",
            "source": "Server header",
            "confidence": "Possible indicator"
        })

    if powered_by:
        technologies.append({
            "name": powered_by,
            "category": "Backend Technology",
            "source": "X-Powered-By header",
            "confidence": "Possible indicator"
        })

    header_indicators = {
        "cloudflare": ("Cloudflare", "CDN / Security"),
        "x-vercel-id": ("Vercel", "Hosting Platform"),
        "x-nf-request-id": ("Netlify", "Hosting Platform"),
        "x-amz-cf-id": ("Amazon CloudFront", "CDN"),
        "x-shopify-stage": ("Shopify", "E-commerce Platform"),
        "x-drupal-cache": ("Drupal", "CMS"),
        "x-generator": ("Possible CMS / Framework", "Web Technology")
    }

    lower_headers = {
        key.lower(): str(value)
        for key, value in headers.items()
    }

    for header, details in header_indicators.items():
        if header in lower_headers:
            technologies.append({
                "name": details[0],
                "category": details[1],
                "source": header,
                "confidence": "Possible indicator"
            })

    unique = []
    seen = set()

    for item in technologies:
        key = (item["name"], item["category"])

        if key not in seen:
            seen.add(key)
            unique.append(item)

    return unique
