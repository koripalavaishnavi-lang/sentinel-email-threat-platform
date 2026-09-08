from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

from urllib.parse import urlparse

import base64
import ipaddress
import os
import re

import requests
from dotenv import load_dotenv


# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY",
    ""
).strip()

ABUSEIPDB_API_KEY = os.getenv(
    "ABUSEIPDB_API_KEY",
    ""
).strip()


# Treat placeholder keys as empty
if VIRUSTOTAL_API_KEY in [
    "",
    "YOUR_VIRUSTOTAL_KEY",
    "your_virustotal_key"
]:
    VIRUSTOTAL_API_KEY = ""


if ABUSEIPDB_API_KEY in [
    "",
    "YOUR_ABUSEIPDB_KEY",
    "your_abuseipdb_key"
]:
    ABUSEIPDB_API_KEY = ""


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="SENTINEL Email Threat Intelligence API",
    description="Email forensic analysis and threat intelligence platform",
    version="2.1.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,

    # Local development
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ],

    # Allow Render frontend subdomains
    allow_origin_regex=r"^https://[a-zA-Z0-9-]+\.onrender\.com$",

    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# BASIC ROUTES
# ============================================================

@app.get("/")
def root():
    return {
        "message": "SENTINEL Email Threat Intelligence API is running"
    }


@app.get("/api/health")
def health():
    return {
        "status": "online",
        "service": "SENTINEL"
    }


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):
    if not text:
        return []

    pattern = r"""https?://[^\s<>"']+"""

    urls = re.findall(
        pattern,
        text
    )

    cleaned_urls = []

    for url in urls:
        url = url.rstrip(
            ".,;:!?)]}"
        )

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domains(urls):
    domains = []

    for url in urls:
        try:
            parsed = urlparse(url)

            domain = parsed.netloc

            if "@" in domain:
                domain = domain.split("@")[-1]

            domain = domain.split(":")[0]

            if domain:
                domain = domain.lower()

                if domain not in domains:
                    domains.append(domain)

        except Exception:
            continue

    return domains


# ============================================================
# IP EXTRACTION
# ============================================================

def extract_ip_addresses(text):
    if not text:
        return []

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    candidates = re.findall(
        pattern,
        text
    )

    valid_ips = []

    for ip in candidates:
        try:
            ipaddress.ip_address(ip)

            if ip not in valid_ips:
                valid_ips.append(ip)

        except ValueError:
            continue

    return valid_ips


# ============================================================
# PUBLIC IP CHECK
# ============================================================

def is_public_ip(ip):
    try:
        address = ipaddress.ip_address(ip)
        return address.is_global

    except ValueError:
        return False


# ============================================================
# EMAIL BODY
# ============================================================

def get_email_body(message):
    body = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            disposition = str(
                part.get(
                    "Content-Disposition",
                    ""
                )
            )

            if (
                content_type == "text/plain"
                and "attachment" not in disposition.lower()
            ):
                try:
                    body += part.get_content()

                except Exception:
                    pass

    else:

        try:
            body = message.get_content()

        except Exception:
            body = ""

    return body


# ============================================================
# RECEIVED HEADERS
# ============================================================

def get_received_headers(message):
    return message.get_all(
        "Received",
        []
    )


# ============================================================
# AUTHENTICATION
# ============================================================

def analyze_authentication(message):

    spf = message.get(
        "Received-SPF"
    )

    authentication_results = message.get(
        "Authentication-Results"
    )

    dkim = message.get(
        "DKIM-Signature"
    )

    if spf:
        spf_status = spf
    else:
        spf_status = "Not Found"

    if dkim:
        dkim_status = "Found"
    else:
        dkim_status = "Not Found"

    if authentication_results:
        auth_results = authentication_results
    else:
        auth_results = "Not available"

    return {
        "spf": spf_status,
        "dkim": dkim_status,
        "authentication_results": auth_results
    }


# ============================================================
# GEOLOCATION
# ============================================================

def get_ip_geolocation(ip):

    if not is_public_ip(ip):
        return None

    try:

        response = requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=5
        )

        if response.status_code != 200:
            return None

        data = response.json()

        return {
            "ip": ip,
            "country": data.get("country_name"),
            "country_code": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "postal": data.get("postal"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "timezone": data.get("timezone"),
            "asn": data.get("asn"),
            "organization": data.get("org")
        }

    except Exception as e:

        print(
            f"Geolocation error for {ip}: {e}"
        )

        return None


# ============================================================
# VIRUSTOTAL
# ============================================================

def virus_total_headers():

    return {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }


def normalize_vt_status(stats):

    if not stats:
        return "UNKNOWN"

    malicious = stats.get(
        "malicious",
        0
    )

    suspicious = stats.get(
        "suspicious",
        0
    )

    if malicious > 0:
        return "MALICIOUS"

    if suspicious > 0:
        return "SUSPICIOUS"

    return "CLEAN"


def calculate_vt_confidence(stats):

    if not stats:
        return 0

    malicious = stats.get(
        "malicious",
        0
    )

    suspicious = stats.get(
        "suspicious",
        0
    )

    harmless = stats.get(
        "harmless",
        0
    )

    undetected = stats.get(
        "undetected",
        0
    )

    total = (
        malicious
        + suspicious
        + harmless
        + undetected
    )

    if total == 0:
        return 0

    threat_count = (
        malicious
        + suspicious
    )

    return round(
        (threat_count / total) * 100
    )


# ============================================================
# VIRUSTOTAL IP
# ============================================================

def check_virustotal_ip(ip):

    result = {
        "indicator": ip,
        "type": "IP",
        "status": "UNKNOWN",
        "confidence": 0,
        "source": "VirusTotal",
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0
    }

    if not VIRUSTOTAL_API_KEY:

        result["source"] = (
            "VirusTotal API key not configured"
        )

        return result

    try:

        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=virus_total_headers(),
            timeout=10
        )

        if response.status_code != 200:

            result["source"] = (
                f"VirusTotal HTTP {response.status_code}"
            )

            return result

        data = response.json()

        attributes = (
            data.get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        for key in [
            "malicious",
            "suspicious",
            "harmless",
            "undetected"
        ]:

            result[key] = stats.get(
                key,
                0
            )

        result["status"] = normalize_vt_status(
            stats
        )

        result["confidence"] = calculate_vt_confidence(
            stats
        )

        return result

    except Exception as e:

        print(
            f"VirusTotal IP error: {e}"
        )

        result["source"] = (
            "VirusTotal request failed"
        )

        return result


# ============================================================
# VIRUSTOTAL DOMAIN
# ============================================================

def check_virustotal_domain(domain):

    result = {
        "indicator": domain,
        "type": "DOMAIN",
        "status": "UNKNOWN",
        "confidence": 0,
        "source": "VirusTotal",
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0
    }

    if not VIRUSTOTAL_API_KEY:

        result["source"] = (
            "VirusTotal API key not configured"
        )

        return result

    try:

        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=virus_total_headers(),
            timeout=10
        )

        if response.status_code != 200:

            result["source"] = (
                f"VirusTotal HTTP {response.status_code}"
            )

            return result

        data = response.json()

        attributes = (
            data.get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        for key in [
            "malicious",
            "suspicious",
            "harmless",
            "undetected"
        ]:

            result[key] = stats.get(
                key,
                0
            )

        result["status"] = normalize_vt_status(
            stats
        )

        result["confidence"] = calculate_vt_confidence(
            stats
        )

        return result

    except Exception as e:

        print(
            f"VirusTotal domain error: {e}"
        )

        result["source"] = (
            "VirusTotal request failed"
        )

        return result


# ============================================================
# VIRUSTOTAL URL
# ============================================================

def encode_url_for_virustotal(url):

    return base64.urlsafe_b64encode(
        url.encode()
    ).decode().rstrip("=")


def check_virustotal_url(url):

    result = {
        "indicator": url,
        "type": "URL",
        "status": "UNKNOWN",
        "confidence": 0,
        "source": "VirusTotal",
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0
    }

    if not VIRUSTOTAL_API_KEY:

        result["source"] = (
            "VirusTotal API key not configured"
        )

        return result

    try:

        url_id = encode_url_for_virustotal(
            url
        )

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=virus_total_headers(),
            timeout=10
        )

        if response.status_code != 200:

            result["source"] = (
                f"VirusTotal HTTP {response.status_code}"
            )

            return result

        data = response.json()

        attributes = (
            data.get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        for key in [
            "malicious",
            "suspicious",
            "harmless",
            "undetected"
        ]:

            result[key] = stats.get(
                key,
                0
            )

        result["status"] = normalize_vt_status(
            stats
        )

        result["confidence"] = calculate_vt_confidence(
            stats
        )

        return result

    except Exception as e:

        print(
            f"VirusTotal URL error: {e}"
        )

        result["source"] = (
            "VirusTotal request failed"
        )

        return result


# ============================================================
# ABUSEIPDB
# ============================================================

def check_abuseipdb(ip):

    result = {
        "indicator": ip,
        "type": "IP",
        "status": "UNKNOWN",
        "confidence": 0,
        "source": "AbuseIPDB",
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "country_code": None,
        "isp": None,
        "domain": None
    }

    if not ABUSEIPDB_API_KEY:

        result["source"] = (
            "AbuseIPDB API key not configured"
        )

        return result

    if not is_public_ip(ip):

        result["source"] = (
            "Private/non-public IP"
        )

        return result

    try:

        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=10
        )

        if response.status_code != 200:

            result["source"] = (
                f"AbuseIPDB HTTP {response.status_code}"
            )

            return result

        data = response.json().get(
            "data",
            {}
        )

        abuse_score = data.get(
            "abuseConfidenceScore",
            0
        )

        total_reports = data.get(
            "totalReports",
            0
        )

        result["abuse_confidence_score"] = (
            abuse_score
        )

        result["confidence"] = abuse_score

        result["total_reports"] = (
            total_reports
        )

        result["country_code"] = data.get(
            "countryCode"
        )

        result["isp"] = data.get(
            "isp"
        )

        result["domain"] = data.get(
            "domain"
        )

        if abuse_score >= 70:

            result["status"] = "MALICIOUS"

        elif abuse_score >= 25:

            result["status"] = "SUSPICIOUS"

        else:

            result["status"] = "CLEAN"

        return result

    except Exception as e:

        print(
            f"AbuseIPDB error: {e}"
        )

        result["source"] = (
            "AbuseIPDB request failed"
        )

        return result


# ============================================================
# LOCAL TEST INTELLIGENCE
# ============================================================

def local_ip_intelligence(ip):

    known_ips = {

        "8.8.8.8": {
            "status": "CLEAN",
            "confidence": 95,
            "source": "SENTINEL Test Intelligence"
        }

    }

    if ip in known_ips:

        data = known_ips[ip]

        return {
            "indicator": ip,
            "type": "IP",
            "status": data["status"],
            "confidence": data["confidence"],
            "source": data["source"]
        }

    return None


def local_domain_intelligence(domain):

    known_domains = {

        "example.com": {
            "status": "CLEAN",
            "confidence": 90,
            "source": "SENTINEL Test Intelligence"
        },

        "google.com": {
            "status": "CLEAN",
            "confidence": 90,
            "source": "SENTINEL Test Intelligence"
        },

        "microsoft.com": {
            "status": "CLEAN",
            "confidence": 90,
            "source": "SENTINEL Test Intelligence"
        }

    }

    domain = domain.lower()

    if domain in known_domains:

        data = known_domains[domain]

        return {
            "indicator": domain,
            "type": "DOMAIN",
            "status": data["status"],
            "confidence": data["confidence"],
            "source": data["source"],
            "malicious": 0,
            "suspicious": 0
        }

    return None


# ============================================================
# COMBINED IP THREAT INTELLIGENCE
# ============================================================

def check_ip_threat_intelligence(ip):

    # Real APIs first

    virustotal = check_virustotal_ip(
        ip
    )

    abuseipdb = check_abuseipdb(
        ip
    )

    statuses = [
        virustotal["status"],
        abuseipdb["status"]
    ]

    # If either API has a real result

    if (
        "MALICIOUS" in statuses
        or
        "SUSPICIOUS" in statuses
        or
        "CLEAN" in statuses
    ):

        if "MALICIOUS" in statuses:

            overall_status = "MALICIOUS"

        elif "SUSPICIOUS" in statuses:

            overall_status = "SUSPICIOUS"

        else:

            overall_status = "CLEAN"

        confidence_values = [
            virustotal.get(
                "confidence",
                0
            ),
            abuseipdb.get(
                "confidence",
                0
            )
        ]

        available = [
            x
            for x in confidence_values
            if x > 0
        ]

        confidence = (
            max(available)
            if available
            else 0
        )

        return {
            "indicator": ip,
            "type": "IP",
            "status": overall_status,
            "confidence": confidence,
            "sources": {
                "virustotal": virustotal,
                "abuseipdb": abuseipdb
            }
        }

    # Local fallback for demo/testing

    local_result = local_ip_intelligence(
        ip
    )

    if local_result:

        return {
            "indicator": ip,
            "type": "IP",
            "status": local_result["status"],
            "confidence": local_result["confidence"],
            "source": local_result["source"],
            "sources": {
                "virustotal": virustotal,
                "abuseipdb": abuseipdb
            }
        }

    return {
        "indicator": ip,
        "type": "IP",
        "status": "UNKNOWN",
        "confidence": 0,
        "source": "SENTINEL Local Intelligence",
        "sources": {
            "virustotal": virustotal,
            "abuseipdb": abuseipdb
        }
    }


# ============================================================
# DOMAIN INTELLIGENCE
# ============================================================

def check_domain_threat_intelligence(domain):

    result = check_virustotal_domain(
        domain
    )

    # If VirusTotal returned useful data

    if result["status"] != "UNKNOWN":
        return result

    # Local fallback

    local_result = local_domain_intelligence(
        domain
    )

    if local_result:
        return local_result

    return result


# ============================================================
# URL INTELLIGENCE
# ============================================================

def check_url_threat_intelligence(url):

    result = check_virustotal_url(
        url
    )

    return result


# ============================================================
# RISK ANALYSIS
# ============================================================

def calculate_risk(
    subject,
    body,
    urls,
    domains,
    ip_addresses,
    authentication,
    threat_intelligence
):

    score = 0

    reasons = []

    subject_lower = (
        subject or ""
    ).lower()

    body_lower = (
        body or ""
    ).lower()

    combined_text = (
        subject_lower
        + " "
        + body_lower
    )

    # SPF

    if authentication["spf"] == "Not Found":

        score += 10

        reasons.append(
            "SPF authentication not found"
        )

    # DKIM

    if authentication["dkim"] == "Not Found":

        score += 10

        reasons.append(
            "DKIM signature not found"
        )

    # URLs

    if urls:

        score += min(
            len(urls) * 5,
            20
        )

        reasons.append(
            f"{len(urls)} URL(s) found"
        )

    # IP addresses

    if ip_addresses:

        public_ip_count = sum(
            1
            for ip in ip_addresses
            if is_public_ip(ip)
        )

        score += min(
            public_ip_count * 5,
            15
        )

        if public_ip_count > 0:

            reasons.append(
                f"{public_ip_count} public IP address(es) found"
            )

    # Suspicious keywords

    suspicious_keywords = [

        "urgent",
        "verify your account",
        "verify account",
        "password",
        "login",
        "click here",
        "security alert",
        "account suspended",
        "account locked",
        "confirm your account",
        "bank",
        "payment required",
        "reset password",
        "limited time",
        "winner",
        "congratulations",
        "invoice",
        "wire transfer"

    ]

    found_keywords = []

    for keyword in suspicious_keywords:

        if keyword in combined_text:

            found_keywords.append(
                keyword
            )

    if found_keywords:

        score += min(
            len(found_keywords) * 5,
            25
        )

        reasons.append(
            "Suspicious/phishing keywords detected"
        )

    # Threat intelligence

    all_indicators = (
        threat_intelligence.get(
            "ips",
            []
        )
        +
        threat_intelligence.get(
            "domains",
            []
        )
        +
        threat_intelligence.get(
            "urls",
            []
        )
    )

    malicious_indicators = []

    suspicious_indicators = []

    for indicator in all_indicators:

        status = indicator.get(
            "status",
            "UNKNOWN"
        )

        if status == "MALICIOUS":

            malicious_indicators.append(
                indicator.get("indicator")
            )

        elif status == "SUSPICIOUS":

            suspicious_indicators.append(
                indicator.get("indicator")
            )

    if malicious_indicators:

        score += min(
            len(malicious_indicators) * 30,
            70
        )

        reasons.append(
            "Threat intelligence identified "
            f"{len(malicious_indicators)} malicious indicator(s)"
        )

    if suspicious_indicators:

        score += min(
            len(suspicious_indicators) * 15,
            40
        )

        reasons.append(
            "Threat intelligence identified "
            f"{len(suspicious_indicators)} suspicious indicator(s)"
        )

    score = min(
        score,
        100
    )

    if score >= 70:

        risk_level = "HIGH"

    elif score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    return {
        "score": score,
        "level": risk_level,
        "reasons": reasons
    }


# ============================================================
# EMAIL ANALYSIS
# ============================================================

@app.post("/api/analyze-email")
async def analyze_email(
    file: UploadFile = File(...)
):

    try:

        file_bytes = await file.read()

        if not file_bytes:

            return {
                "success": False,
                "error": "Uploaded file is empty"
            }

        # Parse email

        message = BytesParser(
            policy=policy.default
        ).parsebytes(
            file_bytes
        )

        # Basic information

        sender = message.get(
            "From",
            "Unknown"
        )

        recipient = message.get(
            "To",
            "Unknown"
        )

        reply_to = message.get(
            "Reply-To",
            "Not specified"
        )

        subject = message.get(
            "Subject",
            "No Subject"
        )

        date = message.get(
            "Date",
            "Unknown"
        )

        # Date

        try:

            parsed_date = parsedate_to_datetime(
                date
            )

            formatted_date = parsed_date.strftime(
                "%Y-%m-%d %H:%M:%S %z"
            )

        except Exception:

            formatted_date = date

        # Body

        body = get_email_body(
            message
        )

        # Headers

        header_text = str(
            message
        )

        # URLs

        body_urls = extract_urls(
            body
        )

        header_urls = extract_urls(
            header_text
        )

        urls = list(
            dict.fromkeys(
                body_urls
                +
                header_urls
            )
        )

        # Domains

        domains = extract_domains(
            urls
        )

        # IPs

        header_ips = extract_ip_addresses(
            header_text
        )

        body_ips = extract_ip_addresses(
            body
        )

        ip_addresses = list(
            dict.fromkeys(
                header_ips
                +
                body_ips
            )
        )

        # Received headers

        received_headers = get_received_headers(
            message
        )

        # Authentication

        authentication = analyze_authentication(
            message
        )

        # ====================================================
        # GEOLOCATION
        # ====================================================

        geolocation = []

        for ip in ip_addresses:

            if is_public_ip(ip):

                location = get_ip_geolocation(
                    ip
                )

                if location:

                    geolocation.append(
                        location
                    )

        # ====================================================
        # IP THREAT INTELLIGENCE
        # ====================================================

        ip_intelligence = []

        for ip in ip_addresses:

            if is_public_ip(ip):

                print(
                    f"Checking IP intelligence: {ip}"
                )

                result = check_ip_threat_intelligence(
                    ip
                )

                ip_intelligence.append(
                    result
                )

        # ====================================================
        # DOMAIN THREAT INTELLIGENCE
        # ====================================================

        domain_intelligence = []

        for domain in domains:

            print(
                f"Checking domain intelligence: {domain}"
            )

            result = check_domain_threat_intelligence(
                domain
            )

            domain_intelligence.append(
                result
            )

        # ====================================================
        # URL THREAT INTELLIGENCE
        # ====================================================

        url_intelligence = []

        for url in urls:

            print(
                f"Checking URL intelligence: {url}"
            )

            result = check_url_threat_intelligence(
                url
            )

            url_intelligence.append(
                result
            )

        # ====================================================
        # INTELLIGENCE SUMMARY
        # ====================================================

        all_intelligence = (
            ip_intelligence
            +
            domain_intelligence
            +
            url_intelligence
        )

        malicious_count = 0
        suspicious_count = 0
        clean_count = 0
        unknown_count = 0

        for indicator in all_intelligence:

            status = indicator.get(
                "status",
                "UNKNOWN"
            )

            if status == "MALICIOUS":

                malicious_count += 1

            elif status == "SUSPICIOUS":

                suspicious_count += 1

            elif status == "CLEAN":

                clean_count += 1

            else:

                unknown_count += 1

        threat_intelligence = {

            "ips": ip_intelligence,

            "domains": domain_intelligence,

            "urls": url_intelligence,

            "summary": {

                "total_indicators":
                    len(all_intelligence),

                "malicious":
                    malicious_count,

                "suspicious":
                    suspicious_count,

                "clean":
                    clean_count,

                "unknown":
                    unknown_count

            }

        }

        # ====================================================
        # RISK
        # ====================================================

        risk = calculate_risk(

            subject=subject,

            body=body,

            urls=urls,

            domains=domains,

            ip_addresses=ip_addresses,

            authentication=authentication,

            threat_intelligence=threat_intelligence

        )

        # ====================================================
        # RESPONSE
        # ====================================================

        return {

            "success": True,

            "email": {

                "filename":
                    file.filename,

                "sender":
                    sender,

                "recipient":
                    recipient,

                "reply_to":
                    reply_to,

                "date":
                    formatted_date,

                "subject":
                    subject

            },

            "forensics": {

                "urls":
                    urls,

                "domains":
                    domains,

                "ip_addresses":
                    ip_addresses,

                "received_headers":
                    received_headers

            },

            "authentication":
                authentication,

            "geolocation":
                geolocation,

            "threat_intelligence":
                threat_intelligence,

            "risk": {

                "score":
                    risk["score"],

                "level":
                    risk["level"],

                "reasons":
                    risk["reasons"]

            },

            "body":
                body

        }

    except Exception as e:

        print(
            f"Email analysis error: {e}"
        )

        return {

            "success": False,

            "error":
                str(e)

        }


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                "8000"
            )
        )
    )