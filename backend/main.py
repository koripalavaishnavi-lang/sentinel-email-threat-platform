from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
from pypdf import PdfReader
from dotenv import load_dotenv

import base64
import io
import ipaddress
import os
import re
import requests


# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()

if VIRUSTOTAL_API_KEY.lower() in ("", "your_virustotal_key"):
    VIRUSTOTAL_API_KEY = ""

if ABUSEIPDB_API_KEY.lower() in ("", "your_abuseipdb_key"):
    ABUSEIPDB_API_KEY = ""


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="SENTINEL Email Threat Intelligence API",
    description="Email forensic analysis and threat intelligence platform",
    version="3.0.1",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ],
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
        "service": "SENTINEL",
    }


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):
    if not text:
        return []

    pattern = r"""https?://[^\s<>"']+"""
    urls = re.findall(pattern, text)

    cleaned = []

    for url in urls:
        url = url.rstrip(".,;:!?)]}")

        if url not in cleaned:
            cleaned.append(url)

    return cleaned


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

            domain = domain.split(":")[0].lower()

            if domain and domain not in domains:
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
    candidates = re.findall(pattern, text)

    valid_ips = []

    for ip in candidates:
        try:
            ipaddress.ip_address(ip)

            if ip not in valid_ips:
                valid_ips.append(ip)

        except ValueError:
            continue

    return valid_ips


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# ============================================================
# EML EXTRACTION
# ============================================================

def get_email_body(message):
    body = ""

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            disposition = str(
                part.get("Content-Disposition", "")
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


def get_received_headers(message):
    return message.get_all("Received", [])


def analyze_authentication(message):
    spf = message.get("Received-SPF")
    dkim = message.get("DKIM-Signature")
    authentication_results = message.get(
        "Authentication-Results"
    )

    return {
        "spf": spf if spf else "Not Found",
        "dkim": "Found" if dkim else "Not Found",
        "authentication_results": (
            authentication_results
            if authentication_results
            else "Not available"
        ),
    }


# ============================================================
# PDF EXTRACTION
# ============================================================

def extract_pdf_text(file_bytes):
    try:
        reader = PdfReader(io.BytesIO(file_bytes))
        pages = []

        for page in reader.pages:
            page_text = page.extract_text()

            if page_text:
                pages.append(page_text)

        return "\n".join(pages).strip()

    except Exception as exc:
        raise ValueError(f"Unable to read PDF: {exc}")


def extract_pdf_email_fields(text):
    def find_field(patterns, default):
        for pattern in patterns:
            match = re.search(
                pattern,
                text,
                re.IGNORECASE | re.MULTILINE,
            )

            if match:
                value = match.group(1).strip()

                if value:
                    return value

        return default

    return {
        "sender": find_field(
            [
                r"^\s*From\s*:\s*(.+)$",
                r"^\s*Sender\s*:\s*(.+)$",
            ],
            "Unknown",
        ),
        "recipient": find_field(
            [
                r"^\s*To\s*:\s*(.+)$",
                r"^\s*Recipient\s*:\s*(.+)$",
            ],
            "Unknown",
        ),
        "reply_to": find_field(
            [
                r"^\s*Reply-To\s*:\s*(.+)$",
                r"^\s*Reply To\s*:\s*(.+)$",
            ],
            "Not specified",
        ),
        "subject": find_field(
            [
                r"^\s*Subject\s*:\s*(.+)$",
            ],
            "No Subject",
        ),
        "date": find_field(
            [
                r"^\s*Date\s*:\s*(.+)$",
                r"^\s*Sent\s*:\s*(.+)$",
            ],
            "Unknown",
        ),
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
            timeout=5,
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
            "organization": data.get("org"),
        }

    except Exception as exc:
        print(f"Geolocation error for {ip}: {exc}")
        return None


# ============================================================
# VIRUSTOTAL
# ============================================================

def virustotal_headers():
    return {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
    }


def normalize_vt_status(stats):
    if not stats:
        return "UNKNOWN"

    if stats.get("malicious", 0) > 0:
        return "MALICIOUS"

    if stats.get("suspicious", 0) > 0:
        return "SUSPICIOUS"

    return "CLEAN"


def calculate_vt_confidence(stats):
    if not stats:
        return 0

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total = (
        malicious
        + suspicious
        + harmless
        + undetected
    )

    if total == 0:
        return 0

    return round(
        ((malicious + suspicious) / total) * 100
    )


def empty_vt_result(indicator, indicator_type):
    return {
        "indicator": indicator,
        "type": indicator_type,
        "status": "UNKNOWN",
        "confidence": 0,
        "source": "VirusTotal",
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
    }


def parse_vt_response(response, result):
    if response.status_code != 200:
        result["source"] = (
            f"VirusTotal HTTP {response.status_code}"
        )
        return result

    attributes = (
        response.json()
        .get("data", {})
        .get("attributes", {})
    )

    stats = attributes.get(
        "last_analysis_stats",
        {},
    )

    for key in (
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
    ):
        result[key] = stats.get(key, 0)

    result["status"] = normalize_vt_status(stats)
    result["confidence"] = calculate_vt_confidence(stats)

    return result


def check_virustotal_ip(ip):
    result = empty_vt_result(ip, "IP")

    if not VIRUSTOTAL_API_KEY:
        result["source"] = (
            "VirusTotal API key not configured"
        )
        return result

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=virustotal_headers(),
            timeout=10,
        )

        return parse_vt_response(response, result)

    except Exception as exc:
        print(f"VirusTotal IP error: {exc}")
        result["source"] = "VirusTotal request failed"
        return result


def check_virustotal_domain(domain):
    result = empty_vt_result(domain, "DOMAIN")

    if not VIRUSTOTAL_API_KEY:
        result["source"] = (
            "VirusTotal API key not configured"
        )
        return result

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=virustotal_headers(),
            timeout=10,
        )

        return parse_vt_response(response, result)

    except Exception as exc:
        print(f"VirusTotal domain error: {exc}")
        result["source"] = "VirusTotal request failed"
        return result


def encode_url_for_virustotal(url):
    return base64.urlsafe_b64encode(
        url.encode()
    ).decode().rstrip("=")


def check_virustotal_url(url):
    result = empty_vt_result(url, "URL")

    if not VIRUSTOTAL_API_KEY:
        result["source"] = (
            "VirusTotal API key not configured"
        )
        return result

    try:
        url_id = encode_url_for_virustotal(url)

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=virustotal_headers(),
            timeout=10,
        )

        return parse_vt_response(response, result)

    except Exception as exc:
        print(f"VirusTotal URL error: {exc}")
        result["source"] = "VirusTotal request failed"
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
        "domain": None,
    }

    if not ABUSEIPDB_API_KEY:
        result["source"] = (
            "AbuseIPDB API key not configured"
        )
        return result

    if not is_public_ip(ip):
        result["source"] = "Private/non-public IP"
        return result

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
            },
            timeout=10,
        )

        if response.status_code != 200:
            result["source"] = (
                f"AbuseIPDB HTTP {response.status_code}"
            )
            return result

        data = response.json().get("data", {})
        score = data.get(
            "abuseConfidenceScore",
            0,
        )

        result["abuse_confidence_score"] = score
        result["confidence"] = score
        result["total_reports"] = data.get(
            "totalReports",
            0,
        )
        result["country_code"] = data.get(
            "countryCode"
        )
        result["isp"] = data.get("isp")
        result["domain"] = data.get("domain")

        if score >= 70:
            result["status"] = "MALICIOUS"
        elif score >= 25:
            result["status"] = "SUSPICIOUS"
        else:
            result["status"] = "CLEAN"

        return result

    except Exception as exc:
        print(f"AbuseIPDB error: {exc}")
        result["source"] = "AbuseIPDB request failed"
        return result


# ============================================================
# LOCAL TEST INTELLIGENCE
# ============================================================

def local_ip_intelligence(ip):
    known_ips = {
        "8.8.8.8": {
            "status": "CLEAN",
            "confidence": 95,
            "source": "SENTINEL Test Intelligence",
        }
    }

    if ip in known_ips:
        data = known_ips[ip]

        return {
            "indicator": ip,
            "type": "IP",
            "status": data["status"],
            "confidence": data["confidence"],
            "source": data["source"],
        }

    return None


def local_domain_intelligence(domain):
    known_domains = {
        "example.com": 90,
        "google.com": 90,
        "microsoft.com": 90,
    }

    confidence = known_domains.get(
        domain.lower()
    )

    if confidence is None:
        return None

    return {
        "indicator": domain.lower(),
        "type": "DOMAIN",
        "status": "CLEAN",
        "confidence": confidence,
        "source": "SENTINEL Test Intelligence",
        "malicious": 0,
        "suspicious": 0,
    }


# ============================================================
# COMBINED THREAT INTELLIGENCE
# ============================================================

def check_ip_threat_intelligence(ip):
    virustotal = check_virustotal_ip(ip)
    abuseipdb = check_abuseipdb(ip)

    statuses = [
        virustotal["status"],
        abuseipdb["status"],
    ]

    if "MALICIOUS" in statuses:
        overall_status = "MALICIOUS"
    elif "SUSPICIOUS" in statuses:
        overall_status = "SUSPICIOUS"
    elif "CLEAN" in statuses:
        overall_status = "CLEAN"
    else:
        overall_status = "UNKNOWN"

    confidence_values = [
        virustotal.get("confidence", 0),
        abuseipdb.get("confidence", 0),
    ]

    confidence = (
        max(confidence_values)
        if any(confidence_values)
        else 0
    )

    source = "Combined threat intelligence"

    if overall_status == "UNKNOWN":
        local_result = local_ip_intelligence(ip)

        if local_result:
            overall_status = local_result["status"]
            confidence = local_result["confidence"]
            source = local_result["source"]
        else:
            source = "SENTINEL Local Intelligence"

    return {
        "indicator": ip,
        "type": "IP",
        "status": overall_status,
        "confidence": confidence,
        "source": source,
        "sources": {
            "virustotal": virustotal,
            "abuseipdb": abuseipdb,
        },
    }


def check_domain_threat_intelligence(domain):
    result = check_virustotal_domain(domain)

    if result["status"] != "UNKNOWN":
        return result

    local_result = local_domain_intelligence(domain)

    if local_result:
        return local_result

    return result


def check_url_threat_intelligence(url):
    return check_virustotal_url(url)


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
    threat_intelligence,
):
    score = 0
    reasons = []

    combined_text = (
        f"{subject or ''} {body or ''}"
    ).lower()

    if authentication["spf"] == "Not Found":
        score += 10
        reasons.append(
            "SPF authentication not found"
        )

    if authentication["dkim"] == "Not Found":
        score += 10
        reasons.append(
            "DKIM signature not found"
        )

    if urls:
        score += min(len(urls) * 5, 20)
        reasons.append(
            f"{len(urls)} URL(s) found"
        )

    public_ip_count = sum(
        1
        for ip in ip_addresses
        if is_public_ip(ip)
    )

    if public_ip_count > 0:
        score += min(public_ip_count * 5, 15)
        reasons.append(
            f"{public_ip_count} public IP address(es) found"
        )

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
        "wire transfer",
    ]

    found_keywords = [
        keyword
        for keyword in suspicious_keywords
        if keyword in combined_text
    ]

    if found_keywords:
        score += min(
            len(found_keywords) * 5,
            25,
        )
        reasons.append(
            "Suspicious/phishing keywords detected"
        )

    indicators = (
        threat_intelligence.get("ips", [])
        + threat_intelligence.get("domains", [])
        + threat_intelligence.get("urls", [])
    )

    malicious_indicators = [
        item.get("indicator")
        for item in indicators
        if item.get("status") == "MALICIOUS"
    ]

    suspicious_indicators = [
        item.get("indicator")
        for item in indicators
        if item.get("status") == "SUSPICIOUS"
    ]

    if malicious_indicators:
        score += min(
            len(malicious_indicators) * 30,
            70,
        )
        reasons.append(
            "Threat intelligence identified "
            f"{len(malicious_indicators)} malicious indicator(s)"
        )

    if suspicious_indicators:
        score += min(
            len(suspicious_indicators) * 15,
            40,
        )
        reasons.append(
            "Threat intelligence identified "
            f"{len(suspicious_indicators)} suspicious indicator(s)"
        )

    score = min(score, 100)

    if score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": score,
        "level": risk_level,
        "reasons": reasons,
    }


# ============================================================
# EMAIL ANALYSIS ENDPOINT
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
                "error": "Uploaded file is empty",
            }

        filename = file.filename or "unknown"
        extension = os.path.splitext(
            filename
        )[1].lower()

        # ----------------------------------------------------
        # PDF FILE
        # ----------------------------------------------------

        if extension == ".pdf":
            body = extract_pdf_text(file_bytes)

            if not body:
                return {
                    "success": False,
                    "error": (
                        "The PDF contains no readable text. "
                        "Please upload a text-based email PDF."
                    ),
                }

            fields = extract_pdf_email_fields(body)

            sender = fields["sender"]
            recipient = fields["recipient"]
            reply_to = fields["reply_to"]
            subject = fields["subject"]
            date = fields["date"]
            formatted_date = date
            header_text = body

            authentication = {
                "spf": "Not available in PDF",
                "dkim": "Not available in PDF",
                "authentication_results": (
                    "Original email authentication headers "
                    "are not available in this PDF"
                ),
            }

            received_headers = []
            source_type = "PDF"

        # ----------------------------------------------------
        # EML FILE
        # ----------------------------------------------------

        elif extension == ".eml":
            message = BytesParser(
                policy=policy.default
            ).parsebytes(file_bytes)

            sender = message.get(
                "From",
                "Unknown",
            )

            recipient = message.get(
                "To",
                "Unknown",
            )

            reply_to = message.get(
                "Reply-To",
                "Not specified",
            )

            subject = message.get(
                "Subject",
                "No Subject",
            )

            date = message.get(
                "Date",
                "Unknown",
            )

            try:
                parsed_date = parsedate_to_datetime(date)

                formatted_date = parsed_date.strftime(
                    "%Y-%m-%d %H:%M:%S %z"
                )

            except Exception:
                formatted_date = date

            body = get_email_body(message)
            header_text = str(message)

            authentication = analyze_authentication(
                message
            )

            received_headers = get_received_headers(
                message
            )

            source_type = "EML"

        else:
            return {
                "success": False,
                "error": (
                    "Unsupported file type. "
                    "Please upload an .eml or .pdf file."
                ),
            }

        # ----------------------------------------------------
        # COMMON EXTRACTION
        # ----------------------------------------------------

        body_urls = extract_urls(body)
        header_urls = extract_urls(header_text)

        urls = list(
            dict.fromkeys(
                body_urls + header_urls
            )
        )

        domains = extract_domains(urls)

        header_ips = extract_ip_addresses(
            header_text
        )

        body_ips = extract_ip_addresses(
            body
        )

        ip_addresses = list(
            dict.fromkeys(
                header_ips + body_ips
            )
        )

        # ----------------------------------------------------
        # GEOLOCATION
        # ----------------------------------------------------

        geolocation = []

        for ip in ip_addresses:
            if is_public_ip(ip):
                location = get_ip_geolocation(ip)

                if location:
                    geolocation.append(location)

        # ----------------------------------------------------
        # IP INTELLIGENCE
        # ----------------------------------------------------

        ip_intelligence = []

        for ip in ip_addresses:
            if is_public_ip(ip):
                ip_intelligence.append(
                    check_ip_threat_intelligence(ip)
                )

        # ----------------------------------------------------
        # DOMAIN INTELLIGENCE
        # ----------------------------------------------------

        domain_intelligence = [
            check_domain_threat_intelligence(domain)
            for domain in domains
        ]

        # ----------------------------------------------------
        # URL INTELLIGENCE
        # ----------------------------------------------------

        url_intelligence = [
            check_url_threat_intelligence(url)
            for url in urls
        ]

        # ----------------------------------------------------
        # INTELLIGENCE SUMMARY
        # ----------------------------------------------------

        all_intelligence = (
            ip_intelligence
            + domain_intelligence
            + url_intelligence
        )

        threat_intelligence = {
            "ips": ip_intelligence,
            "domains": domain_intelligence,
            "urls": url_intelligence,
            "summary": {
                "total_indicators": len(
                    all_intelligence
                ),
                "malicious": sum(
                    1
                    for item in all_intelligence
                    if item.get("status") == "MALICIOUS"
                ),
                "suspicious": sum(
                    1
                    for item in all_intelligence
                    if item.get("status") == "SUSPICIOUS"
                ),
                "clean": sum(
                    1
                    for item in all_intelligence
                    if item.get("status") == "CLEAN"
                ),
                "unknown": sum(
                    1
                    for item in all_intelligence
                    if item.get("status") not in (
                        "MALICIOUS",
                        "SUSPICIOUS",
                        "CLEAN",
                    )
                ),
            },
        }

        # ----------------------------------------------------
        # RISK
        # ----------------------------------------------------

        risk = calculate_risk(
            subject=subject,
            body=body,
            urls=urls,
            domains=domains,
            ip_addresses=ip_addresses,
            authentication=authentication,
            threat_intelligence=threat_intelligence,
        )

        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return {
            "success": True,
            "source_type": source_type,
            "email": {
                "filename": filename,
                "sender": sender,
                "recipient": recipient,
                "reply_to": reply_to,
                "date": formatted_date,
                "subject": subject,
            },
            "forensics": {
                "urls": urls,
                "domains": domains,
                "ip_addresses": ip_addresses,
                "received_headers": received_headers,
            },
            "authentication": authentication,
            "geolocation": geolocation,
            "threat_intelligence": threat_intelligence,
            "risk": risk,
            "body": body,
        }

    except Exception as exc:
        print(f"Email analysis error: {exc}")

        return {
            "success": False,
            "error": str(exc),
        }


# ============================================================
# LOCAL SERVER
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        reload=True,
    )