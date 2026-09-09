from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
from pypdf import PdfReader
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from dotenv import load_dotenv

import base64
import ipaddress
import io
import json
import os
import re
import requests
import secrets
import psycopg2

load_dotenv()

# =========================
# CONFIG
# =========================

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://sentinel-email-threat-backend.onrender.com/api/auth/google/callback"
).strip()

FRONTEND_URL = os.getenv(
    "FRONTEND_URL",
    "https://sentinel-email-threat-platform-1.onrender.com"
).strip()

if VT_KEY.lower() in ("", "your_virustotal_key"):
    VT_KEY = ""

if ABUSE_KEY.lower() in ("", "your_abuseipdb_key"):
    ABUSE_KEY = ""

GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]

gmail_credentials = None

# =========================
# APP
# =========================

app = FastAPI(
    title="SENTINEL Email Threat Intelligence API",
    description="Email forensic analysis and threat intelligence platform",
    version="3.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "https://sentinel-email-threat-platform-1.onrender.com",
        "https://sentinelthreat.in"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# =========================
# BASIC ROUTES
# =========================

@app.get("/")
def root():
    return {
        "message": "SENTINEL Email Threat Intelligence API is running",
        "version": "3.2.0"
    }


@app.get("/api/health")
def health():
    return {
        "status": "online",
        "service": "SENTINEL",
        "version": "3.2.0"
    }


@app.get("/api/debug/google")
def debug_google():
    return {
        "client_id_configured": bool(GOOGLE_CLIENT_ID),
        "client_secret_configured": bool(GOOGLE_CLIENT_SECRET),
        "database_configured": bool(DATABASE_URL),
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "frontend_url": FRONTEND_URL
    }

# =========================
# DATABASE / GMAIL TOKEN
# =========================

def db():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not configured in Render."
        )

    return psycopg2.connect(DATABASE_URL)


def init_gmail_database():
    if not DATABASE_URL:
        print(
            "DATABASE_URL not configured. "
            "Gmail persistence disabled."
        )
        return

    try:
        conn = db()
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS gmail_oauth (
                id INTEGER PRIMARY KEY,
                token TEXT NOT NULL,
                refresh_token TEXT,
                token_uri TEXT NOT NULL,
                scopes TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS gmail_oauth_states (
                state TEXT PRIMARY KEY,
                code_verifier TEXT NOT NULL
            )
        """)

        conn.commit()
        cur.close()
        conn.close()

        print("Gmail OAuth database initialized.")

    except Exception as e:
        print(
            "Gmail database initialization error:",
            e
        )


def save_gmail_credentials(credentials):
    conn = db()
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM gmail_oauth"
    )

    cur.execute("""
        INSERT INTO gmail_oauth
        (id, token, refresh_token, token_uri, scopes)
        VALUES (1, %s, %s, %s, %s)
    """, (
        credentials.token,
        credentials.refresh_token,
        credentials.token_uri,
        json.dumps(
            credentials.scopes or GMAIL_SCOPES
        )
    ))

    conn.commit()
    cur.close()
    conn.close()


def load_gmail_credentials():
    if not DATABASE_URL:
        return None

    try:
        conn = db()
        cur = conn.cursor()

        cur.execute("""
            SELECT
                token,
                refresh_token,
                token_uri,
                scopes
            FROM gmail_oauth
            WHERE id = 1
        """)

        row = cur.fetchone()

        cur.close()
        conn.close()

        if not row:
            return None

        token, refresh_token, token_uri, scopes = row

        return Credentials(
            token=token,
            refresh_token=refresh_token,
            token_uri=token_uri,
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            scopes=json.loads(scopes)
            if scopes else GMAIL_SCOPES
        )

    except Exception as e:
        print(
            "Gmail credential load error:",
            e
        )
        return None


def delete_gmail_credentials():
    if not DATABASE_URL:
        return

    try:
        conn = db()
        cur = conn.cursor()

        cur.execute(
            "DELETE FROM gmail_oauth"
        )

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        print(
            "Gmail credential delete error:",
            e
        )


# =========================
# OAUTH STATE / PKCE
# =========================

def save_oauth_state(state, code_verifier):
    conn = db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO gmail_oauth_states
        (state, code_verifier)
        VALUES (%s, %s)
        ON CONFLICT(state)
        DO UPDATE SET
            code_verifier = EXCLUDED.code_verifier
    """, (
        state,
        code_verifier
    ))

    conn.commit()
    cur.close()
    conn.close()


def load_and_delete_oauth_state(state):
    conn = db()
    cur = conn.cursor()

    cur.execute("""
        SELECT code_verifier
        FROM gmail_oauth_states
        WHERE state = %s
    """, (state,))

    row = cur.fetchone()

    if row:
        cur.execute("""
            DELETE FROM gmail_oauth_states
            WHERE state = %s
        """, (state,))

        conn.commit()

    cur.close()
    conn.close()

    return row[0] if row else None


init_gmail_database()

# =========================
# EXTRACTION
# =========================

def extract_urls(text):
    if not text:
        return []

    found = re.findall(
        r'https?://[^\s<>"\']+',
        text
    )

    return list(dict.fromkeys(
        url.rstrip(".,;:!?)]}")
        for url in found
    ))


def extract_domains(urls):
    result = []

    for url in urls:
        try:
            domain = (
                urlparse(url)
                .netloc
                .split("@")[-1]
                .split(":")[0]
                .lower()
            )

            if domain and domain not in result:
                result.append(domain)

        except Exception:
            pass

    return result


def extract_ip_addresses(text):
    if not text:
        return []

    result = []

    for ip in re.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        text
    ):
        try:
            ipaddress.ip_address(ip)

            if ip not in result:
                result.append(ip)

        except ValueError:
            pass

    return result


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def get_email_body(message):
    if not message.is_multipart():
        try:
            return message.get_content()
        except Exception:
            return ""

    body = ""

    for part in message.walk():
        if (
            part.get_content_type() == "text/plain"
            and "attachment" not in str(
                part.get("Content-Disposition", "")
            ).lower()
        ):
            try:
                body += part.get_content()
            except Exception:
                pass

    return body


def get_received_headers(message):
    return message.get_all(
        "Received",
        []
    )


def analyze_authentication(message):
    return {
        "spf": (
            message.get("Received-SPF")
            or "Not Found"
        ),
        "dkim": (
            "Found"
            if message.get("DKIM-Signature")
            else "Not Found"
        ),
        "authentication_results": (
            message.get("Authentication-Results")
            or "Not available"
        )
    }

# =========================
# PDF
# =========================

def extract_pdf_text(data):
    try:
        reader = PdfReader(
            io.BytesIO(data)
        )

        return "\n".join(
            page.extract_text() or ""
            for page in reader.pages
        ).strip()

    except Exception as e:
        raise ValueError(
            f"Unable to read PDF: {e}"
        )


def extract_pdf_email_fields(text):

    def field(patterns, default):
        for pattern in patterns:
            match = re.search(
                pattern,
                text,
                re.I | re.M
            )

            if match and match.group(1).strip():
                return match.group(1).strip()

        return default

    return {
        "sender": field(
            [
                r"^\s*From\s*:\s*(.+)$",
                r"^\s*Sender\s*:\s*(.+)$"
            ],
            "Unknown"
        ),

        "recipient": field(
            [
                r"^\s*To\s*:\s*(.+)$",
                r"^\s*Recipient\s*:\s*(.+)$"
            ],
            "Unknown"
        ),

        "reply_to": field(
            [
                r"^\s*Reply-To\s*:\s*(.+)$",
                r"^\s*Reply To\s*:\s*(.+)$"
            ],
            "Not specified"
        ),

        "subject": field(
            [
                r"^\s*Subject\s*:\s*(.+)$"
            ],
            "No Subject"
        ),

        "date": field(
            [
                r"^\s*Date\s*:\s*(.+)$",
                r"^\s*Sent\s*:\s*(.+)$"
            ],
            "Unknown"
        )
    }

# =========================
# GEOLOCATION
# =========================

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
            "Geolocation error:",
            e
        )
        return None

# =========================
# VIRUSTOTAL
# =========================

def vt_headers():
    return {
        "x-apikey": VT_KEY,
        "Accept": "application/json"
    }


def vt_status(stats):
    if not stats:
        return "UNKNOWN"

    if stats.get("malicious", 0) > 0:
        return "MALICIOUS"

    if stats.get("suspicious", 0) > 0:
        return "SUSPICIOUS"

    return "CLEAN"


def vt_confidence(stats):
    if not stats:
        return 0

    total = sum(
        stats.get(key, 0)
        for key in (
            "malicious",
            "suspicious",
            "harmless",
            "undetected"
        )
    )

    if not total:
        return 0

    return round(
        (
            stats.get("malicious", 0)
            + stats.get("suspicious", 0)
        )
        / total
        * 100
    )


def check_vt(
    indicator,
    kind,
    endpoint
):
    result = {
        "indicator": indicator,
        "type": kind,
        "status": "UNKNOWN",
        "confidence": 0,
        "source": "VirusTotal",
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0
    }

    if not VT_KEY:
        result["source"] = (
            "VirusTotal API key not configured"
        )
        return result

    try:
        response = requests.get(
            endpoint,
            headers=vt_headers(),
            timeout=10
        )

        if response.status_code != 200:
            result["source"] = (
                f"VirusTotal HTTP "
                f"{response.status_code}"
            )
            return result

        stats = (
            response.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        for key in (
            "malicious",
            "suspicious",
            "harmless",
            "undetected"
        ):
            result[key] = stats.get(key, 0)

        result["status"] = vt_status(stats)
        result["confidence"] = vt_confidence(stats)

    except Exception as e:
        print(
            "VirusTotal error:",
            e
        )

        result["source"] = (
            "VirusTotal request failed"
        )

    return result


def check_virustotal_ip(ip):
    return check_vt(
        ip,
        "IP",
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    )


def check_virustotal_domain(domain):
    return check_vt(
        domain,
        "DOMAIN",
        f"https://www.virustotal.com/api/v3/domains/{domain}"
    )


def check_virustotal_url(url):
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().rstrip("=")

    return check_vt(
        url,
        "URL",
        f"https://www.virustotal.com/api/v3/urls/{url_id}"
    )

# =========================
# ABUSEIPDB
# =========================

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

    if not ABUSE_KEY:
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
                "Key": ABUSE_KEY,
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
                f"AbuseIPDB HTTP "
                f"{response.status_code}"
            )
            return result

        data = response.json().get(
            "data",
            {}
        )

        score = data.get(
            "abuseConfidenceScore",
            0
        )

        result.update({
            "abuse_confidence_score": score,
            "confidence": score,
            "total_reports": data.get(
                "totalReports",
                0
            ),
            "country_code": data.get(
                "countryCode"
            ),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "status": (
                "MALICIOUS"
                if score >= 70
                else "SUSPICIOUS"
                if score >= 25
                else "CLEAN"
            )
        })

    except Exception as e:
        print(
            "AbuseIPDB error:",
            e
        )

        result["source"] = (
            "AbuseIPDB request failed"
        )

    return result

# =========================
# LOCAL INTELLIGENCE
# =========================

def local_ip_intelligence(ip):
    data = {
        "8.8.8.8": {
            "status": "CLEAN",
            "confidence": 95,
            "source": "SENTINEL Test Intelligence"
        }
    }.get(ip)

    if not data:
        return None

    return {
        "indicator": ip,
        "type": "IP",
        **data
    }


def local_domain_intelligence(domain):
    data = {
        "example.com": ("CLEAN", 90),
        "google.com": ("CLEAN", 90),
        "microsoft.com": ("CLEAN", 90)
    }.get(domain.lower())

    if not data:
        return None

    return {
        "indicator": domain,
        "type": "DOMAIN",
        "status": data[0],
        "confidence": data[1],
        "source": "SENTINEL Test Intelligence",
        "malicious": 0,
        "suspicious": 0
    }


def check_ip_threat_intelligence(ip):
    vt = check_virustotal_ip(ip)
    abuse = check_abuseipdb(ip)
    local = local_ip_intelligence(ip)

    if local:
        return local

    statuses = [
        vt["status"],
        abuse["status"]
    ]

    if "MALICIOUS" in statuses:
        overall = "MALICIOUS"
    elif "SUSPICIOUS" in statuses:
        overall = "SUSPICIOUS"
    elif "CLEAN" in statuses:
        overall = "CLEAN"
    else:
        overall = "UNKNOWN"

    return {
        "indicator": ip,
        "type": "IP",
        "status": overall,
        "confidence": max(
            vt["confidence"],
            abuse["confidence"]
        ),
        "source": "Combined Threat Intelligence",
        "sources": {
            "virustotal": vt,
            "abuseipdb": abuse
        }
    }


def check_domain_threat_intelligence(domain):
    vt = check_virustotal_domain(domain)

    if vt["status"] != "UNKNOWN":
        return vt

    return (
        local_domain_intelligence(domain)
        or vt
    )


def check_url_threat_intelligence(url):
    return check_virustotal_url(url)

# =========================
# RISK
# =========================

def calculate_risk(
    subject,
    body,
    urls,
    domains,
    ips,
    auth,
    threat_intelligence
):
    score = 0
    reasons = []

    text = (
        f"{subject or ''} "
        f"{body or ''}"
    ).lower()

    if auth["spf"] == "Not Found":
        score += 10
        reasons.append(
            "SPF authentication not found"
        )

    if auth["dkim"] == "Not Found":
        score += 10
        reasons.append(
            "DKIM signature not found"
        )

    if urls:
        score += min(
            len(urls) * 5,
            20
        )

        reasons.append(
            f"{len(urls)} URL(s) found"
        )

    public_ips = [
        ip for ip in ips
        if is_public_ip(ip)
    ]

    if public_ips:
        score += min(
            len(public_ips) * 5,
            15
        )

        reasons.append(
            f"{len(public_ips)} "
            "public IP address(es) found"
        )

    keywords = [
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

    found = [
        keyword
        for keyword in keywords
        if keyword in text
    ]

    if found:
        score += min(
            len(found) * 5,
            25
        )

        reasons.append(
            "Suspicious/phishing keywords detected"
        )

    indicators = (
        threat_intelligence["ips"]
        + threat_intelligence["domains"]
        + threat_intelligence["urls"]
    )

    malicious = [
        item
        for item in indicators
        if item.get("status") == "MALICIOUS"
    ]

    suspicious = [
        item
        for item in indicators
        if item.get("status") == "SUSPICIOUS"
    ]

    if malicious:
        score += min(
            len(malicious) * 30,
            70
        )

        reasons.append(
            "Threat intelligence identified "
            f"{len(malicious)} "
            "malicious indicator(s)"
        )

    if suspicious:
        score += min(
            len(suspicious) * 15,
            40
        )

        reasons.append(
            "Threat intelligence identified "
            f"{len(suspicious)} "
            "suspicious indicator(s)"
        )

    score = min(
        score,
        100
    )

    return {
        "score": score,
        "level": (
            "HIGH"
            if score >= 70
            else "MEDIUM"
            if score >= 40
            else "LOW"
        ),
        "reasons": reasons
    }

# =========================
# CORE ANALYSIS
# =========================

async def analyze_bytes(
    file_bytes,
    filename
):
    if not file_bytes:
        return {
            "success": False,
            "error": "Uploaded file is empty"
        }

    extension = os.path.splitext(
        filename
    )[1].lower()

    if extension == ".pdf":

        body = extract_pdf_text(
            file_bytes
        )

        if not body:
            return {
                "success": False,
                "error": (
                    "The PDF contains no readable text. "
                    "Please upload a text-based email PDF."
                )
            }

        fields = extract_pdf_email_fields(
            body
        )

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
            )
        }

        received_headers = []
        source_type = "PDF"

    elif extension == ".eml":

        message = BytesParser(
            policy=policy.default
        ).parsebytes(file_bytes)

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

        try:
            formatted_date = (
                parsedate_to_datetime(date)
                .strftime(
                    "%Y-%m-%d %H:%M:%S %z"
                )
            )
        except Exception:
            formatted_date = date

        body = get_email_body(
            message
        )

        header_text = str(message)

        authentication = (
            analyze_authentication(
                message
            )
        )

        received_headers = (
            get_received_headers(
                message
            )
        )

        source_type = "EML"

    else:
        return {
            "success": False,
            "error": (
                "Unsupported file type. "
                "Please upload an .eml or .pdf file."
            )
        }

    urls = list(dict.fromkeys(
        extract_urls(body)
        + extract_urls(header_text)
    ))

    domains = extract_domains(
        urls
    )

    ips = list(dict.fromkeys(
        extract_ip_addresses(
            header_text
        )
        + extract_ip_addresses(body)
    ))

    geolocation = [
        location
        for ip in ips
        if is_public_ip(ip)
        for location in [
            get_ip_geolocation(ip)
        ]
        if location
    ]

    ip_intelligence = [
        check_ip_threat_intelligence(ip)
        for ip in ips
        if is_public_ip(ip)
    ]

    domain_intelligence = [
        check_domain_threat_intelligence(
            domain
        )
        for domain in domains
    ]

    url_intelligence = [
        check_url_threat_intelligence(url)
        for url in urls
    ]

    all_intelligence = (
        ip_intelligence
        + domain_intelligence
        + url_intelligence
    )

    counts = {
        "malicious": sum(
            item.get("status") == "MALICIOUS"
            for item in all_intelligence
        ),
        "suspicious": sum(
            item.get("status") == "SUSPICIOUS"
            for item in all_intelligence
        ),
        "clean": sum(
            item.get("status") == "CLEAN"
            for item in all_intelligence
        ),
        "unknown": sum(
            item.get("status") not in (
                "MALICIOUS",
                "SUSPICIOUS",
                "CLEAN"
            )
            for item in all_intelligence
        )
    }

    threat_intelligence = {
        "ips": ip_intelligence,
        "domains": domain_intelligence,
        "urls": url_intelligence,
        "summary": {
            "total_indicators": len(
                all_intelligence
            ),
            **counts
        }
    }

    risk = calculate_risk(
        subject,
        body,
        urls,
        domains,
        ips,
        authentication,
        threat_intelligence
    )

    return {
        "success": True,
        "source_type": source_type,

        "email": {
            "filename": filename,
            "sender": sender,
            "recipient": recipient,
            "reply_to": reply_to,
            "date": formatted_date,
            "subject": subject
        },

        "forensics": {
            "urls": urls,
            "domains": domains,
            "ip_addresses": ips,
            "received_headers": received_headers
        },

        "authentication": authentication,
        "geolocation": geolocation,
        "threat_intelligence": threat_intelligence,
        "risk": risk,
        "body": body
    }

# =========================
# UPLOAD ANALYSIS
# =========================

@app.post("/api/analyze-email")
async def analyze_email(
    file: UploadFile = File(...)
):
    try:
        data = await file.read()

        return await analyze_bytes(
            data,
            file.filename or "unknown"
        )

    except Exception as e:
        print(
            "EMAIL ANALYSIS ERROR:",
            e
        )

        return {
            "success": False,
            "error": str(e)
        }

# =========================
# GOOGLE OAUTH
# =========================

def google_flow():
    if (
        not GOOGLE_CLIENT_ID
        or not GOOGLE_CLIENT_SECRET
    ):
        raise RuntimeError(
            "Google OAuth is not configured. "
            "Set GOOGLE_CLIENT_ID and "
            "GOOGLE_CLIENT_SECRET in Render."
        )

    config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,

            "auth_uri":
                "https://accounts.google.com/o/oauth2/auth",

            "token_uri":
                "https://oauth2.googleapis.com/token",

            "redirect_uris": [
                GOOGLE_REDIRECT_URI
            ]
        }
    }

    return Flow.from_client_config(
        config,
        scopes=GMAIL_SCOPES,
        redirect_uri=GOOGLE_REDIRECT_URI
    )


@app.get("/api/auth/google")
def google_login():
    try:
        flow = google_flow()

        state = secrets.token_urlsafe(32)

        url, _ = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
            state=state
        )

        # IMPORTANT:
        # Persist PKCE verifier in PostgreSQL.
        save_oauth_state(
            state,
            flow.code_verifier
        )

        print(
            "Google OAuth state saved:",
            state
        )

        return RedirectResponse(url)

    except Exception as e:
        print(
            "Google login error:",
            e
        )

        return {
            "success": False,
            "error": str(e)
        }


@app.get("/api/auth/google/callback")
def google_callback(
    code: str = "",
    state: str = ""
):
    global gmail_credentials

    try:
        if not code or not state:
            print(
                "Google OAuth callback missing code/state."
            )

            return RedirectResponse(
                f"{FRONTEND_URL}?gmail=error"
            )

        # Retrieve the PKCE verifier saved
        # during the authorization request.
        code_verifier = load_and_delete_oauth_state(
            state
        )

        if not code_verifier:
            print(
                "Google OAuth error: "
                "OAuth state/code verifier not found."
            )

            return RedirectResponse(
                f"{FRONTEND_URL}?gmail=error"
            )

        flow = google_flow()

        # Restore PKCE verifier before token exchange.
        flow.code_verifier = code_verifier

        flow.fetch_token(
            code=code
        )

        gmail_credentials = (
            flow.credentials
        )

        save_gmail_credentials(
            gmail_credentials
        )

        print(
            "Google OAuth successful. "
            "Gmail credentials saved."
        )

        return RedirectResponse(
            f"{FRONTEND_URL}?gmail=connected"
        )

    except Exception as e:
        print(
            "Google OAuth error:",
            e
        )

        return RedirectResponse(
            f"{FRONTEND_URL}?gmail=error"
        )

# =========================
# GMAIL SERVICE
# =========================

def gmail_service():
    global gmail_credentials

    if not gmail_credentials:
        gmail_credentials = (
            load_gmail_credentials()
        )

    if not gmail_credentials:
        raise RuntimeError(
            "Gmail is not connected."
        )

    if (
        gmail_credentials.expired
        and gmail_credentials.refresh_token
    ):
        gmail_credentials.refresh(
            Request()
        )

        save_gmail_credentials(
            gmail_credentials
        )

    return build(
        "gmail",
        "v1",
        credentials=gmail_credentials,
        cache_discovery=False
    )

# =========================
# GMAIL STATUS
# =========================

@app.get("/api/gmail/status")
def gmail_status():
    try:
        service = gmail_service()

        profile = (
            service.users()
            .getProfile(
                userId="me"
            )
            .execute()
        )

        return {
            "success": True,
            "connected": True,
            "email": profile.get(
                "emailAddress"
            ),
            "messages_total": profile.get(
                "messagesTotal",
                0
            ),
            "threads_total": profile.get(
                "threadsTotal",
                0
            )
        }

    except Exception as e:
        print(
            "Gmail status error:",
            e
        )

        return {
            "success": True,
            "connected": False
        }


@app.post("/api/gmail/disconnect")
def gmail_disconnect():
    global gmail_credentials

    gmail_credentials = None

    delete_gmail_credentials()

    return {
        "success": True,
        "connected": False
    }

# =========================
# GMAIL MESSAGES
# =========================

@app.get("/api/gmail/messages")
def gmail_messages(
    max_results: int = 20,
    page_token: str = None
):
    try:
        max_results = max(
            1,
            min(
                max_results,
                100
            )
        )

        service = gmail_service()

        args = {
            "userId": "me",
            "maxResults": max_results
        }

        if page_token:
            args["pageToken"] = page_token

        data = (
            service.users()
            .messages()
            .list(**args)
            .execute()
        )

        messages = []

        for item in data.get(
            "messages",
            []
        ):
            message_id = item.get(
                "id"
            )

            if not message_id:
                continue

            try:
                message = (
                    service.users()
                    .messages()
                    .get(
                        userId="me",
                        id=message_id,
                        format="metadata",
                        metadataHeaders=[
                            "From",
                            "To",
                            "Subject",
                            "Date",
                            "Reply-To"
                        ]
                    )
                    .execute()
                )

            except Exception as e:
                print(
                    "Skipping Gmail message:",
                    message_id,
                    e
                )
                continue

            headers = {
                header["name"].lower():
                header["value"]
                for header in message.get(
                    "payload",
                    {}
                ).get(
                    "headers",
                    []
                )
            }

            messages.append({
                "id": message_id,

                "thread_id": message.get(
                    "threadId"
                ),

                "sender": headers.get(
                    "from",
                    "Unknown"
                ),

                "recipient": headers.get(
                    "to",
                    "Unknown"
                ),

                "reply_to": headers.get(
                    "reply-to",
                    "Not specified"
                ),

                "subject": headers.get(
                    "subject",
                    "No Subject"
                ),

                "date": headers.get(
                    "date",
                    "Unknown"
                ),

                "snippet": message.get(
                    "snippet",
                    ""
                ),

                "label_ids": message.get(
                    "labelIds",
                    []
                )
            })

        return {
            "success": True,
            "messages": messages,
            "next_page_token": data.get(
                "nextPageToken"
            )
        }

    except Exception as e:
        print(
            "Gmail messages error:",
            e
        )

        return {
            "success": False,
            "error": str(e)
        }

# =========================
# GMAIL RAW DECODER
# =========================

def decode_gmail_raw(raw):
    padding = "=" * (
        (-len(raw)) % 4
    )

    return base64.urlsafe_b64decode(
        raw + padding
    )

# =========================
# GMAIL EMAIL ANALYSIS
# =========================

@app.get(
    "/api/gmail/analyze/{message_id}"
)
async def analyze_gmail(
    message_id: str
):
    try:
        service = gmail_service()

        # -------------------------
        # Verify message exists
        # -------------------------

        try:
            metadata = (
                service.users()
                .messages()
                .get(
                    userId="me",
                    id=message_id,
                    format="metadata",
                    metadataHeaders=[
                        "From",
                        "To",
                        "Subject",
                        "Date",
                        "Reply-To"
                    ]
                )
                .execute()
            )

        except Exception as e:
            print(
                "Gmail message lookup error:",
                e
            )

            return {
                "success": False,
                "error": (
                    "Gmail message was not found "
                    "in the connected account."
                ),
                "message_id": message_id
            }

        # -------------------------
        # Retrieve raw email
        # -------------------------

        try:
            message = (
                service.users()
                .messages()
                .get(
                    userId="me",
                    id=message_id,
                    format="raw"
                )
                .execute()
            )

        except Exception as e:
            print(
                "Gmail raw message error:",
                e
            )

            return {
                "success": False,
                "error": (
                    "Gmail found the message but "
                    "could not retrieve its raw content."
                ),
                "message_id": message_id
            }

        raw = message.get(
            "raw"
        )

        if not raw:
            return {
                "success": False,
                "error": (
                    "Gmail returned an empty email."
                ),
                "message_id": message_id
            }

        # -------------------------
        # Decode raw email
        # -------------------------

        email_bytes = decode_gmail_raw(
            raw
        )

        # -------------------------
        # Run SENTINEL analysis
        # -------------------------

        result = await analyze_bytes(
            email_bytes,
            f"gmail_{message_id}.eml"
        )

        if result.get("success"):

            result["source_type"] = "GMAIL"

            result["email"][
                "gmail_message_id"
            ] = message_id

            result["email"][
                "gmail_thread_id"
            ] = message.get(
                "threadId"
            )

            result["email"][
                "gmail_metadata"
            ] = metadata

        return result

    except Exception as e:
        print(
            "Gmail analysis error:",
            e
        )

        return {
            "success": False,
            "error": str(e),
            "message_id": message_id
        }

# =========================
# SERVER
# =========================

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