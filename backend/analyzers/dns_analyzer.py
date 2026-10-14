
import ipaddress
import socket

import dns.exception
import dns.resolver


def analyze_dns(hostname):
    """Collect basic DNS intelligence for a hostname."""

    result = {
        "hostname": hostname,
        "available": True,
        "ip_addresses": [],
        "mx_records": [],
        "nameservers": [],
        "findings": [],
    }

    # Reject IP addresses; DNS record lookup is for domain names.
    try:
        ipaddress.ip_address(hostname)
        result["available"] = False
        result["findings"].append({
            "name": "DNS Lookup",
            "status": "info",
            "severity": "informational",
            "evidence": "The target is an IP address, not a domain name.",
        })
        return result
    except ValueError:
        pass

    # Resolve IPv4 addresses.
    try:
        answers = dns.resolver.resolve(
            hostname, "A", lifetime=3
        )
        result["ip_addresses"] = sorted(
            {str(answer) for answer in answers}
        )
    except (
        dns.exception.DNSException,
        socket.gaierror,
        OSError,
    ):
        result["findings"].append({
            "name": "IPv4 DNS Records",
            "status": "warning",
            "severity": "informational",
            "evidence": "No IPv4 address was retrieved.",
        })

    # Resolve IPv6 addresses.
    try:
        answers = dns.resolver.resolve(
            hostname, "AAAA", lifetime=3
        )
        result["ipv6_addresses"] = sorted(
            {str(answer) for answer in answers}
        )
    except dns.exception.DNSException:
        result["ipv6_addresses"] = []

    # Resolve mail servers.
    try:
        answers = dns.resolver.resolve(
            hostname, "MX", lifetime=3
        )
        result["mx_records"] = sorted(
            str(answer) for answer in answers
        )
    except dns.exception.DNSException:
        result["findings"].append({
            "name": "Mail Server Records",
            "status": "info",
            "severity": "informational",
            "evidence": "No MX records were retrieved.",
        })

    # Resolve authoritative name servers.
    try:
        answers = dns.resolver.resolve(
            hostname, "NS", lifetime=3
        )
        result["nameservers"] = sorted(
            str(answer).rstrip(".") for answer in answers
        )
    except dns.exception.DNSException:
        result["findings"].append({
            "name": "Name Server Records",
            "status": "warning",
            "severity": "informational",
            "evidence": "No NS records were retrieved.",
        })

    return result

