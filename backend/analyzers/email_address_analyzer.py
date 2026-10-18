
import re
import requests

EMAIL_REPUTATION_API = "https://api.ffraud.com/public/email/check"

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

    try:
        response = requests.post(
            EMAIL_REPUTATION_API,
            json={"email": email},
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        response.raise_for_status()
        data = response.json()

        if not isinstance(data, dict):
            raise ValueError("Invalid API response")

        domain = email.rsplit("@", 1)[1].lower()
        findings = []

        if data.get("is_disposable") is True:
            findings.append({
                "name": "Disposable Email Address",
                "severity": "high",
                "points": 60,
                "evidence": (
                    "This address belongs to a domain identified "
                    "as a disposable or temporary email provider."
                ),
                "recommendation": (
                    "Verify the address carefully before trusting it."
                )
            })

        if data.get("is_known_spammer") is True:
            findings.append({
                "name": "Known Spammer Indicator",
                "severity": "high",
                "points": 80,
                "evidence": (
                    "The reputation service identifies this address "
                    "as associated with known spam activity."
                ),
                "recommendation": (
                    "Investigate the reputation result before "
                    "trusting the address."
                )
            })

        if data.get("community_blacklisted") is True:
            findings.append({
                "name": "Community Blacklist Match",
                "severity": "high",
                "points": 70,
                "evidence": (
                    "The reputation service reports a community "
                    "blacklist match."
                ),
                "recommendation": (
                    "Review the available reputation information."
                )
            })

        if data.get("is_role_address") is True:
            findings.append({
                "name": "Role-Based Email Address",
                "severity": "low",
                "points": 5,
                "evidence": (
                    "This may be a shared address, such as "
                    "support@ or admin@."
                ),
                "recommendation": (
                    "Check whether a shared address is appropriate."
                )
            })

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

        if not findings:
            findings.append({
                "name": "No Listed Reputation Warnings",
                "severity": "informational",
                "points": 0,
                "evidence": (
                    "No matching warnings were returned by "
                    "the reputation checks performed."
                ),
                "recommendation": (
                    "A clean result does not prove that this "
                    "email address is trustworthy."
                )
            })

        return {
            "success": True,
            "analysis_type": "email-address",
            "email_address": email,
            "domain": data.get("domain") or domain,
            "risk_score": score,
            "risk_level": risk_level,
            "finding_count": len(findings),
            "findings": findings,
            "reputation_intelligence": {
                "provider": "FFraud",
                "available": True,
                "is_disposable": data.get("is_disposable"),
                "valid_format": data.get("valid_format"),
                "is_known_spammer": data.get("is_known_spammer"),
                "community_blacklisted": data.get(
                    "community_blacklisted"
                ),
                "blacklist_reports": data.get("blacklist_reports"),
                "detection_source": data.get("detection_source"),
                "safe_domain": data.get("safe_domain"),
                "is_role_address": data.get("is_role_address")
            },
            "disclaimer": (
                "This analysis uses third-party email reputation "
                "indicators. A clean result does not prove that "
                "an address or its owner is trustworthy."
            )
        }

    except requests.RequestException:
        return {
            "success": False,
            "error": (
                "Email reputation service is unavailable. "
                "Please try again later."
            )
        }

    except ValueError:
        return {
            "success": False,
            "error": (
                "Email reputation service returned an invalid response."
            )
        }

