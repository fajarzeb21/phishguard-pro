import re
import ipaddress
import dns.resolver

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def analyze_email_address(email):
    email = email.strip()

    if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
        return {
            "success": False,
            "error": "Please enter a valid email address."
        }

    domain = email.rsplit("@", 1)[1].lower()

    dns_data = {
        "hostname": domain,
        "available": True,
        "ip_addresses": [],
        "ipv6_addresses": [],
        "mx_records": [],
        "nameservers": [],
        "spf_records": [],
        "dmarc_records": [],
    }

    findings = []

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4

    def lookup(name, record_type):
        try:
            answers = resolver.resolve(name, record_type)
            return [str(answer).strip() for answer in answers]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            return []

    dns_data["ip_addresses"] = lookup(domain, "A")
    dns_data["ipv6_addresses"] = lookup(domain, "AAAA")
    dns_data["mx_records"] = lookup(domain, "MX")
    dns_data["nameservers"] = lookup(domain, "NS")

    txt_records = lookup(domain, "TXT")
    dns_data["spf_records"] = [
        record for record in txt_records
        if "v=spf1" in record.lower()
    ]

    dmarc_records = lookup(f"_dmarc.{domain}", "TXT")
    dns_data["dmarc_records"] = [
        record for record in dmarc_records
        if "v=dmarc1" in record.lower()
    ]

    def add_finding(name, severity, points, evidence, recommendation):
        findings.append({
            "name": name,
            "severity": severity,
            "points": points,
            "evidence": evidence,
            "recommendation": recommendation,
        })

    if not dns_data["mx_records"]:
        add_finding(
            "No MX Records",
            "medium",
            15,
            "No mail exchange records were returned for this domain.",
            "Verify the domain's mail configuration independently."
        )

    if not dns_data["spf_records"]:
        add_finding(
            "SPF Record Not Found",
            "medium",
            10,
            "No SPF policy was found in the domain's TXT records.",
            "Review the domain's email authentication configuration."
        )

    if not dns_data["dmarc_records"]:
        add_finding(
            "DMARC Record Not Found",
            "medium",
            10,
            "No DMARC policy was found for this domain.",
            "Review whether the domain publishes a DMARC policy."
        )

    try:
        ipaddress.ip_address(domain)
        add_finding(
            "IP Address Used",
            "high",
            20,
            "The email domain is an IP address.",
            "Verify the sender carefully."
        )
    except ValueError:
        pass

    if not findings:
        add_finding(
            "No Configuration Warnings Detected",
            "informational",
            0,
            "The configured DNS checks did not identify missing records.",
            "Remember that DNS configuration cannot verify sender identity."
        )

    score = min(
        100,
        sum(finding["points"] for finding in findings)
    )

    if score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "success": True,
        "analysis_type": "email-address",
        "email_address": email,
        "risk_score": score,
        "risk_level": risk_level,
        "finding_count": len(findings),
        "findings": findings,
        "dns_intelligence": dns_data,
        "disclaimer": (
            "This analysis examines email format and public DNS "
            "configuration. Missing DNS records do not prove phishing, "
            "and valid records do not establish that a sender is trustworthy."
        ),
    }