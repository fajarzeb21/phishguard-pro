
import re
import ipaddress
from email import policy
from email.parser import Parser
from urllib.parse import urlparse


URGENT_WORDS = [
    "urgent", "immediately", "act now", "account suspended",
    "account blocked", "verify now", "limited time",
    "within 24 hours", "final warning", "action required",
]

CREDENTIAL_WORDS = [
    "password", "login", "sign in", "verify your account",
    "bank details", "credit card", "one-time password",
    "otp", "security code", "re-enter your credentials",
]

THREAT_WORDS = [
    "your account will be closed", "legal action",
    "permanently suspended", "unusual activity",
    "unauthorized access", "account will be terminated",
]

REWARD_WORDS = [
    "you have won", "claim your prize", "free gift",
    "congratulations", "lottery winner", "claim your reward",
]

URL_PATTERN = re.compile(
    r"""https?://[^\s<>"']+|www\.[^\s<>"']+""",
    re.IGNORECASE,
)

ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".msi",
    ".vbs", ".js", ".jse", ".ps1", ".hta", ".jar",
    ".iso", ".img", ".lnk",
}


def add_finding(findings, title, severity, points, description, evidence):
    findings.append({
        "title": title,
        "severity": severity,
        "points": points,
        "description": description,
        "evidence": evidence,
    })


def extract_urls(text):
    urls = []

    for match in URL_PATTERN.findall(text):
        cleaned = match.rstrip(".,!?;:)]}")

        if cleaned and cleaned not in urls:
            urls.append(cleaned)

    return urls


def inspect_url(raw_url):
    candidate = raw_url if "://" in raw_url else "https://" + raw_url

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if not hostname:
            return None

        hostname = hostname.rstrip(".").lower()

        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        indicators = []

        if parsed.scheme.lower() == "http":
            indicators.append("Uses unencrypted HTTP")

        if parsed.username is not None or parsed.password is not None:
            indicators.append("Contains user-information fields before the hostname")

        if is_ip:
            indicators.append("Uses an IP address instead of a domain name")

        if any(label.startswith("xn--") for label in hostname.split(".")):
            indicators.append("Contains an IDN punycode label")

        if len(hostname.split(".")) >= 5:
            indicators.append("Contains many hostname labels")

        return {
            "url": raw_url,
            "hostname": hostname,
            "indicators": indicators,
        }

    except (ValueError, UnicodeError):
        return {
            "url": raw_url,
            "hostname": None,
            "indicators": ["Could not parse this URL reliably"],
        }


def parse_email_headers(text):
    try:
        message = Parser(policy=policy.default).parsestr(text, headersonly=True)

        return {
            "from": str(message.get("From", "")),
            "reply_to": str(message.get("Reply-To", "")),
            "return_path": str(message.get("Return-Path", "")),
            "authentication_results": str(
                message.get("Authentication-Results", "")
            ),
            "received_spf": str(message.get("Received-SPF", "")),
        }

    except (ValueError, TypeError):
        return {
            "from": "",
            "reply_to": "",
            "return_path": "",
            "authentication_results": "",
            "received_spf": "",
        }


def extract_email_address(value):
    match = re.search(
        r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}",
        value or "",
    )

    return match.group(0).lower() if match else None


def analyze_email(email_text):
    if not isinstance(email_text, str) or not email_text.strip():
        return {
            "success": False,
            "error": "Please provide email text.",
        }

    findings = []
    score = 0
    text = email_text.lower()

    # 1. Urgent language
    urgent_matches = [
        word for word in URGENT_WORDS if word in text
    ]

    if urgent_matches:
        add_finding(
            findings,
            "Urgent Language",
            "medium",
            15,
            "The message uses urgency that may pressure the recipient.",
            ", ".join(urgent_matches),
        )

    # 2. Credential requests
    credential_matches = [
        word for word in CREDENTIAL_WORDS if word in text
    ]

    if credential_matches:
        add_finding(
            findings,
            "Credential-Related Language",
            "high",
            25,
            "The message mentions passwords, account verification, "
            "or sensitive authentication information.",
            ", ".join(credential_matches),
        )

    # 3. Threatening language
    threat_matches = [
        word for word in THREAT_WORDS if word in text
    ]

    if threat_matches:
        add_finding(
            findings,
            "Threatening Language",
            "medium",
            15,
            "The message may use fear or threats to influence the recipient.",
            ", ".join(threat_matches),
        )

    # 4. Unexpected rewards
    reward_matches = [
        word for word in REWARD_WORDS if word in text
    ]

    if reward_matches:
        add_finding(
            findings,
            "Unexpected Reward",
            "medium",
            15,
            "The message mentions a prize or reward that may be deceptive.",
            ", ".join(reward_matches),
        )

    # 5. Extract and inspect links without opening them.
    urls = extract_urls(email_text)
    inspected_urls = []

    for raw_url in urls:
        result = inspect_url(raw_url)

        if result:
            inspected_urls.append(result)

    suspicious_urls = [
        result for result in inspected_urls if result["indicators"]
    ]

    if suspicious_urls:
        details = []

        for result in suspicious_urls:
            details.append(
                result["url"] + ": " + "; ".join(result["indicators"])
            )

        add_finding(
            findings,
            "Suspicious URL Patterns",
            "high",
            25,
            "One or more links contain URL patterns that warrant investigation.",
            " | ".join(details),
        )

    # 6. Inspect sender and reply-to fields if headers are provided.
    headers = parse_email_headers(email_text)

    sender = extract_email_address(headers["from"])
    reply_to = extract_email_address(headers["reply_to"])

    if sender and reply_to:
        sender_domain = sender.rsplit("@", 1)[-1]
        reply_domain = reply_to.rsplit("@", 1)[-1]

        if sender_domain != reply_domain:
            add_finding(
                findings,
                "Sender and Reply-To Domain Mismatch",
                "high",
                20,
                "The sender and reply-to addresses use different domains. "
                "This can be legitimate, but deserves verification.",
                f"From domain: {sender_domain}; Reply-To domain: {reply_domain}",
            )

    # 7. Inspect authentication results if real headers are supplied.
    auth_results = headers["authentication_results"].lower()
    spf_results = headers["received_spf"].lower()

    authentication_failures = []

    if re.search(r"\bdmarc\s*=\s*fail\b", auth_results):
        authentication_failures.append("DMARC failed")

    if re.search(r"\bdkim\s*=\s*fail\b", auth_results):
        authentication_failures.append("DKIM failed")

    if re.search(r"\bspf\s*=\s*fail\b", auth_results):
        authentication_failures.append("SPF failed")

    if re.search(r"\bfail\b", spf_results):
        authentication_failures.append("Received-SPF reports failure")

    if authentication_failures:
        add_finding(
            findings,
            "Email Authentication Failure",
            "high",
            25,
            "The supplied email headers report one or more authentication "
            "failures. These results require context and are not conclusive alone.",
            ", ".join(sorted(set(authentication_failures))),
        )

    # 8. Look for potentially dangerous attachment filenames.
    attachment_matches = sorted({
        extension
        for extension in ATTACHMENT_EXTENSIONS
        if re.search(
            re.escape(extension) + r"(?=[\s\"';,]|$)",
            text,
        )
    })

    if attachment_matches:
        add_finding(
            findings,
            "Potentially Dangerous Attachment Type",
            "high",
            25,
            "The message text mentions file extensions often associated "
            "with executable or script content.",
            ", ".join(attachment_matches),
        )

    # 9. Calculate risk score.
    score = min(100, sum(item["points"] for item in findings))

    if score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not findings:
        findings.append({
            "title": "No Known Indicators Detected",
            "severity": "informational",
            "points": 0,
            "description": (
                "The configured checks did not identify suspicious patterns. "
                "This does not establish that the email is legitimate."
            ),
            "evidence": "No configured patterns matched.",
        })

    recommendations = [
        "Do not click unexpected links or open suspicious attachments.",
        "Verify the sender through a trusted contact method.",
        "Never share passwords or one-time codes through an email link.",
        "Review the original email headers when available.",
        "Treat this score as a screening result, not a definitive verdict.",
    ]

    return {
        "success": True,
        "analysis_type": "email",
        "risk_score": score,
        "risk_level": risk_level,
        "finding_count": len(findings),
        "findings": findings,
        "extracted_urls": inspected_urls,
        "sender_information": {
            "from": headers["from"] or None,
            "reply_to": headers["reply_to"] or None,
            "return_path": headers["return_path"] or None,
        },
        "email_authentication": {
            "authentication_results_provided": bool(auth_results),
            "received_spf_provided": bool(spf_results),
            "reported_failures": sorted(set(authentication_failures)),
        },
        "recommendations": recommendations,
        "disclaimer": (
            "This analysis uses heuristic text, URL, and optional header checks. "
            "It is not a verified probability of phishing. Missing indicators "
            "do not prove an email is safe, and header results are only as "
            "trustworthy as the supplied original message."
        ),
    }

