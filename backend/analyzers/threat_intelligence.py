
import requests

OPENPHISH_API = "https://openphish.eu/api/check"


def check_threat_intelligence(url):
    """Check a URL against the OpenPhish threat-intelligence API."""

    try:
        response = requests.get(
            OPENPHISH_API,
            params={"url": url},
            timeout=8,
        )

        response.raise_for_status()
        data = response.json()

        found = data.get("found") is True
        phishing_info = data.get("phish") or {}

        return {
            "provider": "OpenPhish",
            "available": True,
            "known_phishing": found,
            "target_brand": phishing_info.get("target_brand"),
            "status": phishing_info.get("status"),
            "message": (
                "This URL was found in the OpenPhish database."
                if found
                else "This URL was not found in the OpenPhish database."
            ),
        }

    except (requests.RequestException, ValueError):
        return {
            "provider": "OpenPhish",
            "available": False,
            "known_phishing": False,
            "target_brand": None,
            "status": None,
            "message": "OpenPhish is currently unavailable.",
        }

