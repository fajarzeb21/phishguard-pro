
import ipaddress
import re
from urllib.parse import urlparse, unquote

from analyzers.threat_intelligence import check_threat_intelligence

from analyzers.dns_analyzer import analyze_dns
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "shorturl.at", "ow.ly", "buff.ly", "rebrand.ly", "rb.gy",
    "t.ly", "lnkd.in", "soo.gd", "s.id", "tiny.cc", "bl.ink",
    "trib.al", "short.io", "dub.co", "v.gd",
}

SUSPICIOUS_KEYWORDS = {
    "login", "log-in", "signin", "sign-in", "verify",
    "verification", "account", "password", "passwd",
    "credential", "authenticate", "authentication", "confirm",
    "secure", "security", "update", "wallet", "billing",
    "payment", "invoice", "recover", "recovery", "unlock",
    "suspended", "webscr", "validate", "reset", "banking",
}

BRAND_NAMES = {
    "paypal", "google", "microsoft", "apple", "whatsapp",
    "facebook", "instagram", "amazon", "netflix", "linkedin",
    "dropbox", "adobe", "telegram", "coinbase", "binance",
    "steam", "outlook", "icloud", "yahoo", "dhl", "fedex",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "click", "work", "country",
    "gq", "tk", "ml", "cf", "ga",
}

MAX_URL_LENGTH = 8192


def _add_finding(
    findings,
    name,
    status,
    severity,
    points,
    evidence,
    recommendation,
):
    findings.append({
        "name": name,
        "status": status,
        "severity": severity,
        "points": points,
        "evidence": evidence,
        "recommendation": recommendation,
    })


def _normalize_hostname(hostname):
    try:
        hostname = hostname.rstrip(".").lower()

        if not hostname:
            return None

        try:
            ipaddress.ip_address(hostname)
            return hostname
        except ValueError:
            pass

        hostname = hostname.encode("idna").decode("ascii").lower()

        if len(hostname) > 253:
            return None

        labels = hostname.split(".")

        for label in labels:
            if not label or len(label) > 63:
                return None

            if not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label,
            ):
                return None

        return hostname

    except (UnicodeError, ValueError):
        return None


def _is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _get_registered_domain_candidate(hostname):
    labels = hostname.split(".")

    if len(labels) < 2:
        return hostname

    common_second_level_suffixes = {
        ("co", "uk"), ("org", "uk"), ("ac", "uk"),
        ("com", "au"), ("net", "au"), ("org", "au"),
        ("co", "jp"), ("co", "nz"), ("com", "br"),
        ("com", "cn"), ("com", "sg"), ("com", "pk"),
        ("com", "tr"), ("co", "in"),
    }

    if (
        len(labels) >= 3
        and tuple(labels[-2:]) in common_second_level_suffixes
    ):
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def analyze_url(url):
    findings = []

    # 1. Validate the input.
    if not isinstance(url, str) or not url.strip():
        return {
            "success": False,
            "error": "Please provide a URL.",
        }

    url = url.strip()

    if len(url) > MAX_URL_LENGTH:
        return {
            "success": False,
            "error": "The URL is too long to analyze.",
        }

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        return {
            "success": False,
            "error": "The URL contains invalid control characters.",
        }

    if any(char.isspace() for char in url):
        return {
            "success": False,
            "error": "The URL contains whitespace.",
        }

    # 2. Normalize and validate the URL.
    normalized_url = url if "://" in url else "https://" + url

    try:
        parsed = urlparse(normalized_url)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Unsupported URL scheme.")

        if not parsed.netloc or not parsed.hostname:
            raise ValueError("Missing hostname.")

        port = parsed.port
        raw_hostname = parsed.hostname
        hostname = _normalize_hostname(raw_hostname)

        if not hostname:
            raise ValueError("Invalid hostname.")

    except (ValueError, UnicodeError):
        return {
            "success": False,
            "error": "Please enter a valid HTTP or HTTPS URL.",
        }

    is_ip = _is_ip_address(hostname)
    labels = hostname.split(".")

    # 3. Check for deceptive URL user information.
    if parsed.username is not None or parsed.password is not None:
        _add_finding(
            findings,
            "Potentially Deceptive URL",
            "warning",
            "medium",
            15,
            "The URL contains username or password information before its hostname.",
            "Inspect the actual destination hostname carefully.",
        )

    # 4. HTTPS check.
    if parsed.scheme.lower() == "https":
        _add_finding(
            findings,
            "HTTPS",
            "info",
            "informational",
            0,
            "The URL uses HTTPS.",
            "HTTPS encrypts traffic but does not prove that a website is trustworthy.",
        )
    else:
        _add_finding(
            findings,
            "HTTPS",
            "warning",
            "low",
            5,
            "The URL uses HTTP instead of HTTPS.",
            "Avoid sending sensitive information over unencrypted connections.",
        )

    # 5. IP address hostname.
    if is_ip:
        _add_finding(
            findings,
            "IP-Based Hostname",
            "warning",
            "medium",
            20,
            "The hostname is an IP address rather than a conventional domain name.",
            "Verify the destination independently.",
        )

    # 6. Excessive subdomains.
    if not is_ip and len(labels) >= 5:
        _add_finding(
            findings,
            "Excessive Subdomains",
            "warning",
            "low",
            10,
            f"The hostname contains {len(labels)} labels.",
            "Inspect the full hostname carefully.",
        )

    # 7. URL shortener.
    if hostname in SHORTENER_DOMAINS:
        _add_finding(
            findings,
            "URL Shortener",
            "warning",
            "low",
            10,
            "The hostname belongs to a recognized URL-shortening service.",
            "Verify the final destination before trusting the link.",
        )

    # 8. Suspicious keywords.
    decoded_url = unquote(normalized_url).lower()

    matched_keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if re.search(
            rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])",
            decoded_url,
        )
    )

    if matched_keywords:
        _add_finding(
            findings,
            "Suspicious Keywords",
            "warning",
            "low",
            min(15, len(matched_keywords) * 5),
            "Matched terms: " + ", ".join(matched_keywords),
            "These words can occur on legitimate websites too.",
        )

    # 9. Possible brand impersonation.
    if not is_ip:
        registered_domain = _get_registered_domain_candidate(hostname)
        registered_labels = registered_domain.split(".")
        matched_brands = []

        for brand in BRAND_NAMES:
            suspicious_brand_label = any(
                brand in label and label != brand
                for label in labels[:-1]
            )

            suspicious_registered_label = any(
                brand in label and label != brand
                for label in registered_labels
            )

            if suspicious_brand_label or suspicious_registered_label:
                matched_brands.append(brand)

        if matched_brands:
            _add_finding(
                findings,
                "Possible Brand Impersonation",
                "warning",
                "medium",
                20,
                "Brand-like text appears within a hostname label: "
                + ", ".join(sorted(set(matched_brands))),
                "Compare the domain with the organization's official domain.",
            )

    # 10. Percent encoding.
    if re.search(r"%[0-9a-fA-F]{2}", normalized_url):
        _add_finding(
            findings,
            "URL Encoding",
            "info",
            "informational",
            0,
            "The URL contains percent-encoded characters.",
            "Encoding is common on legitimate websites.",
        )

    # 11. Non-standard port.
    if port is not None and port not in {80, 443}:
        _add_finding(
            findings,
            "Non-Standard Port",
            "warning",
            "low",
            5,
            f"The URL uses port {port}.",
            "Verify whether this port is expected.",
        )

    # 12. Potentially risky TLD.
    if not is_ip:
        tld = hostname.split(".")[-1]

        if tld in SUSPICIOUS_TLDS:
            _add_finding(
                findings,
                "Potentially Risky TLD",
                "info",
                "low",
                5,
                f"The hostname uses the .{tld} top-level domain.",
                "A TLD alone cannot establish malicious intent.",
            )

    # 13. Punycode.
    if not is_ip and any(label.startswith("xn--") for label in labels):
        _add_finding(
            findings,
            "Internationalized Domain",
            "info",
            "informational",
            0,
            "The hostname contains an IDNA-encoded label.",
            "Check for lookalike characters when assessing the domain.",
        )

    # 14. Long hostname.
    if len(hostname) > 100:
        _add_finding(
            findings,
            "Long Hostname",
            "warning",
            "low",
            5,
            f"The hostname contains {len(hostname)} characters.",
            "Verify the destination carefully.",
        )

    # 15. Multiple hyphens.
    if not is_ip:
        hyphen_count = hostname.count("-")

        if hyphen_count >= 4:
            _add_finding(
                findings,
                "Multiple Hostname Hyphens",
                "info",
                "low",
                5,
                f"The hostname contains {hyphen_count} hyphens.",
                "Check whether the hostname imitates a known organization.",
            )

    # 16. OpenPhish threat-intelligence lookup.
    threat_intelligence = check_threat_intelligence(normalized_url)
    # DNS intelligence
    dns_intelligence = analyze_dns(hostname)
    print("DNS ANALYSIS RESULT:", dns_intelligence)
    if (
        threat_intelligence.get("available") is True
        and threat_intelligence.get("known_phishing") is True
    ):
        _add_finding(
            findings,
            "Known Phishing URL",
            "warning",
            "high",
            100,
            threat_intelligence.get(
                "message",
                "This URL appears in the OpenPhish database.",
            ),
            "Do not open this URL or enter personal information.",
        )

    # 17. Calculate the risk score.
    score = min(100, sum(item["points"] for item in findings))

    if threat_intelligence.get("known_phishing") is True:
        risk_level = "High"
    elif score >= 50:
        risk_level = "High"
    elif score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # 18. Return results.
    return {
        "success": True,
        "url": normalized_url,
        "hostname": hostname,
        "risk_score": score,
        "risk_level": risk_level,
        "finding_count": len(findings),
        "findings": findings,
         "dns_intelligence": dns_intelligence,
        "threat_intelligence": threat_intelligence,
        "disclaimer": (
            "This result combines heuristic URL indicators with an "
            "available threat-intelligence lookup. A URL not found in "
            "the database is not necessarily safe. A low score does "
            "not prove that a URL is safe."
        ),
    }

