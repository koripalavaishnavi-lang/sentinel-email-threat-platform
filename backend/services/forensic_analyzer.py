import re
import ipaddress
from urllib.parse import urlparse


def extract_urls(text):
    """
    Extract URLs from email text.
    """

    if not text:
        return []

    pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(pattern, text)

    # Remove duplicates
    return list(dict.fromkeys(urls))


def extract_ips(text):
    """
    Extract IPv4 addresses from email text and headers.
    """

    if not text:
        return []

    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    candidates = re.findall(pattern, text)

    valid_ips = []

    for ip in candidates:
        try:
            ipaddress.ip_address(ip)

            if ip not in valid_ips:
                valid_ips.append(ip)

        except ValueError:
            pass

    return valid_ips


def extract_domains(urls):
    """
    Extract domain names from URLs.
    """

    domains = []

    for url in urls:

        try:
            parsed = urlparse(url)

            domain = parsed.hostname

            if domain and domain not in domains:
                domains.append(domain)

        except Exception:
            pass

    return domains


def analyze_headers(email_message):
    """
    Extract important email authentication headers.
    """

    authentication_results = email_message.get(
        "Authentication-Results",
        ""
    )

    received_spf = email_message.get(
        "Received-SPF",
        ""
    )

    dkim_signature = email_message.get(
        "DKIM-Signature",
        ""
    )

    return {
        "authentication_results": authentication_results,
        "received_spf": received_spf,
        "dkim_present": bool(dkim_signature),
        "spf_present": bool(received_spf),
    }


def extract_received_headers(email_message):
    """
    Extract Received headers for email routing investigation.
    """

    received_headers = email_message.get_all(
        "Received",
        []
    )

    return received_headers


def calculate_initial_risk(
    urls,
    ips,
    authentication
):
    """
    Basic rule-based risk score.

    This is NOT our final AI risk model.
    """

    score = 0
    reasons = []

    if urls:
        score += 10
        reasons.append(
            "Email contains one or more URLs."
        )

    if len(urls) >= 3:
        score += 10
        reasons.append(
            "Email contains multiple URLs."
        )

    if ips:
        score += 10
        reasons.append(
            "Email contains IP addresses."
        )

    if not authentication["spf_present"]:
        score += 10
        reasons.append(
            "SPF information was not found."
        )

    if not authentication["dkim_present"]:
        score += 10
        reasons.append(
            "DKIM signature was not found."
        )

    score = min(score, 100)

    if score >= 60:
        level = "HIGH"

    elif score >= 30:
        level = "MEDIUM"

    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }