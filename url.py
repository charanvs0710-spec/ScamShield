import re
from urllib.parse import urlparse


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly"
}


def analyze_url(url):
    score = 0
    findings = []

    parsed = urlparse(url)

    hostname = parsed.hostname
    port = parsed.port

    if not hostname:
        return 0, ["Invalid URL structure"]

    hostname = hostname.lower()

    # Protocol
    if parsed.scheme.lower() == "http":
        score += 5
        findings.append("URL uses HTTP instead of HTTPS")

    # IP address
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname):
        score += 25
        findings.append(f"Raw IP address detected: {hostname}")
    else:
        findings.append(f"Domain detected: {hostname}")

    # Port
    if port:
        findings.append(f"Port detected: {port}")

        if port not in {80, 443}:
            score += 15
            findings.append(
                f"Non-standard port detected: {port}"
            )

    # URL shortener
    if hostname in SHORTENERS:
        score += 20
        findings.append(
            "URL uses a link-shortening service"
        )

    # Punycode
    if "xn--" in hostname:
        score += 20
        findings.append(
            "Possible look-alike punycode domain detected"
        )

    # Username/password
    if parsed.username or parsed.password:
        score += 25
        findings.append(
            "URL contains embedded login information"
        )

    # Too many subdomains
    parts = hostname.split(".")

    if len(parts) >= 5:
        score += 15
        findings.append(
            "URL contains an unusually large number of subdomains"
        )

    # Long URL
    if len(url) > 100:
        score += 10
        findings.append(
            "URL is unusually long"
        )

    # @ symbol
    if "@" in url:
        score += 15
        findings.append(
            "URL contains '@' character"
        )

    score = min(score, 100)

    if not findings:
        findings.append(
            "No major technical warning signs found"
        )

    return score, findings