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
import base64, ipaddress, io, json, os, re, requests, secrets, psycopg2

load_dotenv()

VT_KEY=os.getenv("VIRUSTOTAL_API_KEY","").strip()
ABUSE_KEY=os.getenv("ABUSEIPDB_API_KEY","").strip()
GOOGLE_CLIENT_ID=os.getenv("GOOGLE_CLIENT_ID","").strip()
GOOGLE_CLIENT_SECRET=os.getenv("GOOGLE_CLIENT_SECRET","").strip()
DATABASE_URL=os.getenv("DATABASE_URL","").strip()
GOOGLE_REDIRECT_URI=os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://sentinel-email-threat-backend.onrender.com/api/auth/google/callback"
).strip()
FRONTEND_URL=os.getenv(
    "FRONTEND_URL",
    "https://sentinel-email-threat-platform-1.onrender.com"
).strip()

if VT_KEY.lower() in ("","your_virustotal_key"): VT_KEY=""
if ABUSE_KEY.lower() in ("","your_abuseipdb_key"): ABUSE_KEY=""

GMAIL_SCOPES=["https://www.googleapis.com/auth/gmail.readonly"]
gmail_credentials=None
oauth_states=set()

app=FastAPI(
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

@app.get("/")
def root():
    return {"message":"SENTINEL Email Threat Intelligence API is running","version":"3.2.0"}

@app.get("/api/health")
def health():
    return {"status":"online","service":"SENTINEL","version":"3.2.0"}

@app.get("/api/debug/google")
def debug_google():
    return {
        "client_id_configured":bool(GOOGLE_CLIENT_ID),
        "client_secret_configured":bool(GOOGLE_CLIENT_SECRET),
        "database_configured":bool(DATABASE_URL),
        "redirect_uri":GOOGLE_REDIRECT_URI,
        "frontend_url":FRONTEND_URL
    }

# =========================
# DATABASE / GMAIL TOKEN
# =========================

def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured in Render.")
    return psycopg2.connect(DATABASE_URL)

def init_gmail_database():
    if not DATABASE_URL:
        print("DATABASE_URL not configured. Gmail persistence disabled.")
        return
    try:
        conn=db()
        cur=conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS gmail_oauth(
                id INTEGER PRIMARY KEY,
                token TEXT NOT NULL,
                refresh_token TEXT,
                token_uri TEXT NOT NULL,
                scopes TEXT NOT NULL
            )
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("Gmail OAuth database initialized.")
    except Exception as e:
        print("Gmail database initialization error:",e)

def save_gmail_credentials(c):
    conn=db()
    cur=conn.cursor()
    cur.execute("DELETE FROM gmail_oauth")
    cur.execute("""
        INSERT INTO gmail_oauth
        (id,token,refresh_token,token_uri,scopes)
        VALUES(1,%s,%s,%s,%s)
    """,(
        c.token,
        c.refresh_token,
        c.token_uri,
        json.dumps(c.scopes or GMAIL_SCOPES)
    ))
    conn.commit()
    cur.close()
    conn.close()

def load_gmail_credentials():
    if not DATABASE_URL:
        return None
    try:
        conn=db()
        cur=conn.cursor()
        cur.execute("""
            SELECT token,refresh_token,token_uri,scopes
            FROM gmail_oauth WHERE id=1
        """)
        row=cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return None
        token,refresh_token,token_uri,scopes=row
        return Credentials(
            token=token,
            refresh_token=refresh_token,
            token_uri=token_uri,
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            scopes=json.loads(scopes)
        )
    except Exception as e:
        print("Gmail credential load error:",e)
        return None

def delete_gmail_credentials():
    if not DATABASE_URL:
        return
    try:
        conn=db()
        cur=conn.cursor()
        cur.execute("DELETE FROM gmail_oauth")
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print("Gmail credential delete error:",e)

init_gmail_database()

# =========================
# EXTRACTION
# =========================

def extract_urls(text):
    if not text:return []
    return list(dict.fromkeys(
        u.rstrip(".,;:!?)]}")
        for u in re.findall(r'https?://[^\s<>"\']+',text)
    ))

def extract_domains(urls):
    result=[]
    for u in urls:
        try:
            d=urlparse(u).netloc.split("@")[-1].split(":")[0].lower()
            if d and d not in result: result.append(d)
        except: pass
    return result

def extract_ip_addresses(text):
    if not text:return []
    result=[]
    for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',text):
        try:
            ipaddress.ip_address(ip)
            if ip not in result: result.append(ip)
        except ValueError: pass
    return result

def is_public_ip(ip):
    try:return ipaddress.ip_address(ip).is_global
    except:return False

def get_email_body(message):
    if not message.is_multipart():
        try:return message.get_content()
        except:return ""
    body=""
    for part in message.walk():
        if part.get_content_type()=="text/plain" and "attachment" not in str(
            part.get("Content-Disposition","")
        ).lower():
            try:body+=part.get_content()
            except:pass
    return body

def get_received_headers(message):
    return message.get_all("Received",[])

def analyze_authentication(message):
    return {
        "spf":message.get("Received-SPF") or "Not Found",
        "dkim":"Found" if message.get("DKIM-Signature") else "Not Found",
        "authentication_results":message.get("Authentication-Results") or "Not available"
    }

# =========================
# PDF
# =========================

def extract_pdf_text(data):
    try:
        reader=PdfReader(io.BytesIO(data))
        return "\n".join(page.extract_text() or "" for page in reader.pages).strip()
    except Exception as e:
        raise ValueError(f"Unable to read PDF: {e}")

def extract_pdf_email_fields(text):
    def field(patterns,default):
        for p in patterns:
            m=re.search(p,text,re.I|re.M)
            if m and m.group(1).strip(): return m.group(1).strip()
        return default
    return {
        "sender":field([r"^\s*From\s*:\s*(.+)$",r"^\s*Sender\s*:\s*(.+)$"],"Unknown"),
        "recipient":field([r"^\s*To\s*:\s*(.+)$",r"^\s*Recipient\s*:\s*(.+)$"],"Unknown"),
        "reply_to":field([r"^\s*Reply-To\s*:\s*(.+)$",r"^\s*Reply To\s*:\s*(.+)$"],"Not specified"),
        "subject":field([r"^\s*Subject\s*:\s*(.+)$"],"No Subject"),
        "date":field([r"^\s*Date\s*:\s*(.+)$",r"^\s*Sent\s*:\s*(.+)$"],"Unknown")
    }

# =========================
# GEOLOCATION
# =========================

def get_ip_geolocation(ip):
    if not is_public_ip(ip): return None
    try:
        r=requests.get(f"https://ipapi.co/{ip}/json/",timeout=5)
        if r.status_code!=200:return None
        d=r.json()
        return {
            "ip":ip,
            "country":d.get("country_name"),
            "country_code":d.get("country_code"),
            "region":d.get("region"),
            "city":d.get("city"),
            "postal":d.get("postal"),
            "latitude":d.get("latitude"),
            "longitude":d.get("longitude"),
            "timezone":d.get("timezone"),
            "asn":d.get("asn"),
            "organization":d.get("org")
        }
    except Exception as e:
        print("Geolocation error:",e)
        return None

# =========================
# VIRUSTOTAL
# =========================

def vt_headers():
    return {"x-apikey":VT_KEY,"Accept":"application/json"}

def vt_status(stats):
    if not stats:return "UNKNOWN"
    if stats.get("malicious",0)>0:return "MALICIOUS"
    if stats.get("suspicious",0)>0:return "SUSPICIOUS"
    return "CLEAN"

def vt_confidence(stats):
    if not stats:return 0
    total=sum(stats.get(k,0) for k in
              ("malicious","suspicious","harmless","undetected"))
    return round(
        (stats.get("malicious",0)+stats.get("suspicious",0))/total*100
    ) if total else 0

def check_vt(indicator,kind,endpoint):
    result={
        "indicator":indicator,"type":kind,"status":"UNKNOWN",
        "confidence":0,"source":"VirusTotal",
        "malicious":0,"suspicious":0,"harmless":0,"undetected":0
    }
    if not VT_KEY:
        result["source"]="VirusTotal API key not configured"
        return result
    try:
        r=requests.get(endpoint,headers=vt_headers(),timeout=10)
        if r.status_code!=200:
            result["source"]=f"VirusTotal HTTP {r.status_code}"
            return result
        stats=r.json().get("data",{}).get("attributes",{}).get(
            "last_analysis_stats",{}
        )
        for k in ("malicious","suspicious","harmless","undetected"):
            result[k]=stats.get(k,0)
        result["status"]=vt_status(stats)
        result["confidence"]=vt_confidence(stats)
    except Exception:
        result["source"]="VirusTotal request failed"
    return result

def check_virustotal_ip(ip):
    return check_vt(
        ip,"IP",
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    )

def check_virustotal_domain(domain):
    return check_vt(
        domain,"DOMAIN",
        f"https://www.virustotal.com/api/v3/domains/{domain}"
    )

def check_virustotal_url(url):
    uid=base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return check_vt(
        url,"URL",
        f"https://www.virustotal.com/api/v3/urls/{uid}"
    )

# =========================
# ABUSEIPDB
# =========================

def check_abuseipdb(ip):
    result={
        "indicator":ip,"type":"IP","status":"UNKNOWN",
        "confidence":0,"source":"AbuseIPDB",
        "abuse_confidence_score":0,"total_reports":0,
        "country_code":None,"isp":None,"domain":None
    }
    if not ABUSE_KEY:
        result["source"]="AbuseIPDB API key not configured"
        return result
    if not is_public_ip(ip):
        result["source"]="Private/non-public IP"
        return result
    try:
        r=requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key":ABUSE_KEY,"Accept":"application/json"},
            params={"ipAddress":ip,"maxAgeInDays":90},
            timeout=10
        )
        if r.status_code!=200:
            result["source"]=f"AbuseIPDB HTTP {r.status_code}"
            return result
        d=r.json().get("data",{})
        score=d.get("abuseConfidenceScore",0)
        result.update({
            "abuse_confidence_score":score,
            "confidence":score,
            "total_reports":d.get("totalReports",0),
            "country_code":d.get("countryCode"),
            "isp":d.get("isp"),
            "domain":d.get("domain"),
            "status":"MALICIOUS" if score>=70 else
                     "SUSPICIOUS" if score>=25 else "CLEAN"
        })
    except:
        result["source"]="AbuseIPDB request failed"
    return result

# =========================
# LOCAL INTELLIGENCE
# =========================

def local_ip_intelligence(ip):
    data={"8.8.8.8":{"status":"CLEAN","confidence":95,
                     "source":"SENTINEL Test Intelligence"}}.get(ip)
    return {"indicator":ip,"type":"IP",**data} if data else None

def local_domain_intelligence(domain):
    data={
        "example.com":("CLEAN",90),
        "google.com":("CLEAN",90),
        "microsoft.com":("CLEAN",90)
    }.get(domain.lower())
    if not data:return None
    return {
        "indicator":domain,"type":"DOMAIN",
        "status":data[0],"confidence":data[1],
        "source":"SENTINEL Test Intelligence",
        "malicious":0,"suspicious":0
    }

def check_ip_threat_intelligence(ip):
    vt=check_virustotal_ip(ip)
    abuse=check_abuseipdb(ip)
    local=local_ip_intelligence(ip)
    if local:return local
    statuses=[vt["status"],abuse["status"]]
    if "MALICIOUS" in statuses:
        overall="MALICIOUS"
    elif "SUSPICIOUS" in statuses:
        overall="SUSPICIOUS"
    elif "CLEAN" in statuses:
        overall="CLEAN"
    else:
        overall="UNKNOWN"
    return {
        "indicator":ip,"type":"IP","status":overall,
        "confidence":max(vt["confidence"],abuse["confidence"]),
        "source":"Combined Threat Intelligence",
        "sources":{"virustotal":vt,"abuseipdb":abuse}
    }

def check_domain_threat_intelligence(domain):
    vt=check_virustotal_domain(domain)
    if vt["status"]!="UNKNOWN":return vt
    return local_domain_intelligence(domain) or vt

def check_url_threat_intelligence(url):
    return check_virustotal_url(url)

# =========================
# RISK
# =========================

def calculate_risk(subject,body,urls,domains,ips,auth,ti):
    score=0
    reasons=[]
    text=f"{subject or ''} {body or ''}".lower()

    if auth["spf"]=="Not Found":
        score+=10
        reasons.append("SPF authentication not found")
    if auth["dkim"]=="Not Found":
        score+=10
        reasons.append("DKIM signature not found")
    if urls:
        score+=min(len(urls)*5,20)
        reasons.append(f"{len(urls)} URL(s) found")

    public=[ip for ip in ips if is_public_ip(ip)]
    if public:
        score+=min(len(public)*5,15)
        reasons.append(f"{len(public)} public IP address(es) found")

    keywords=[
        "urgent","verify your account","verify account","password",
        "login","click here","security alert","account suspended",
        "account locked","confirm your account","bank","payment required",
        "reset password","limited time","winner","congratulations",
        "invoice","wire transfer"
    ]
    found=[k for k in keywords if k in text]
    if found:
        score+=min(len(found)*5,25)
        reasons.append("Suspicious/phishing keywords detected")

    indicators=ti["ips"]+ti["domains"]+ti["urls"]
    malicious=[x for x in indicators if x.get("status")=="MALICIOUS"]
    suspicious=[x for x in indicators if x.get("status")=="SUSPICIOUS"]

    if malicious:
        score+=min(len(malicious)*30,70)
        reasons.append(
            f"Threat intelligence identified {len(malicious)} malicious indicator(s)"
        )
    if suspicious:
        score+=min(len(suspicious)*15,40)
        reasons.append(
            f"Threat intelligence identified {len(suspicious)} suspicious indicator(s)"
        )

    score=min(score,100)
    return {
        "score":score,
        "level":"HIGH" if score>=70 else "MEDIUM" if score>=40 else "LOW",
        "reasons":reasons
    }

# =========================
# CORE ANALYSIS
# =========================

async def analyze_bytes(file_bytes,filename):
    if not file_bytes:
        return {"success":False,"error":"Uploaded file is empty"}

    ext=os.path.splitext(filename)[1].lower()

    if ext==".pdf":
        body=extract_pdf_text(file_bytes)
        if not body:
            return {
                "success":False,
                "error":"The PDF contains no readable text. Please upload a text-based email PDF."
            }
        fields=extract_pdf_email_fields(body)
        sender=fields["sender"]
        recipient=fields["recipient"]
        reply_to=fields["reply_to"]
        subject=fields["subject"]
        date=fields["date"]
        formatted_date=date
        header_text=body
        authentication={
            "spf":"Not available in PDF",
            "dkim":"Not available in PDF",
            "authentication_results":
                "Original email authentication headers are not available in this PDF"
        }
        received_headers=[]
        source_type="PDF"

    elif ext==".eml":
        message=BytesParser(policy=policy.default).parsebytes(file_bytes)
        sender=message.get("From","Unknown")
        recipient=message.get("To","Unknown")
        reply_to=message.get("Reply-To","Not specified")
        subject=message.get("Subject","No Subject")
        date=message.get("Date","Unknown")
        try:
            formatted_date=parsedate_to_datetime(date).strftime(
                "%Y-%m-%d %H:%M:%S %z"
            )
        except:
            formatted_date=date
        body=get_email_body(message)
        header_text=str(message)
        authentication=analyze_authentication(message)
        received_headers=get_received_headers(message)
        source_type="EML"

    else:
        return {
            "success":False,
            "error":"Unsupported file type. Please upload an .eml or .pdf file."
        }

    urls=list(dict.fromkeys(
        extract_urls(body)+extract_urls(header_text)
    ))
    domains=extract_domains(urls)
    ips=list(dict.fromkeys(
        extract_ip_addresses(header_text)+extract_ip_addresses(body)
    ))

    geolocation=[
        loc for ip in ips if is_public_ip(ip)
        for loc in [get_ip_geolocation(ip)] if loc
    ]

    ip_intel=[
        check_ip_threat_intelligence(ip)
        for ip in ips if is_public_ip(ip)
    ]
    domain_intel=[
        check_domain_threat_intelligence(d)
        for d in domains
    ]
    url_intel=[
        check_url_threat_intelligence(u)
        for u in urls
    ]

    all_intel=ip_intel+domain_intel+url_intel

    counts={
        "malicious":sum(x.get("status")=="MALICIOUS" for x in all_intel),
        "suspicious":sum(x.get("status")=="SUSPICIOUS" for x in all_intel),
        "clean":sum(x.get("status")=="CLEAN" for x in all_intel),
        "unknown":sum(
            x.get("status") not in ("MALICIOUS","SUSPICIOUS","CLEAN")
            for x in all_intel
        )
    }

    ti={
        "ips":ip_intel,
        "domains":domain_intel,
        "urls":url_intel,
        "summary":{"total_indicators":len(all_intel),**counts}
    }

    risk=calculate_risk(
        subject,body,urls,domains,ips,authentication,ti
    )

    return {
        "success":True,
        "source_type":source_type,
        "email":{
            "filename":filename,
            "sender":sender,
            "recipient":recipient,
            "reply_to":reply_to,
            "date":formatted_date,
            "subject":subject
        },
        "forensics":{
            "urls":urls,
            "domains":domains,
            "ip_addresses":ips,
            "received_headers":received_headers
        },
        "authentication":authentication,
        "geolocation":geolocation,
        "threat_intelligence":ti,
        "risk":risk,
        "body":body
    }

@app.post("/api/analyze-email")
async def analyze_email(file:UploadFile=File(...)):
    try:
        data=await file.read()
        return await analyze_bytes(data,file.filename or "unknown")
    except Exception as e:
        print("EMAIL ANALYSIS ERROR:",e)
        return {"success":False,"error":str(e)}

# =========================
# GOOGLE OAUTH
# =========================

def google_flow():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise RuntimeError(
            "Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Render."
        )

    config={
        "web":{
            "client_id":GOOGLE_CLIENT_ID,
            "client_secret":GOOGLE_CLIENT_SECRET,
            "auth_uri":"https://accounts.google.com/o/oauth2/auth",
            "token_uri":"https://oauth2.googleapis.com/token",
            "redirect_uris":[GOOGLE_REDIRECT_URI]
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
        flow=google_flow()
        state=secrets.token_urlsafe(32)
        oauth_states.add(state)

        url,_=flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
            state=state
        )

        return RedirectResponse(url)
    except Exception as e:
        return {"success":False,"error":str(e)}

@app.get("/api/auth/google/callback")
def google_callback(code:str="",state:str=""):
    global gmail_credentials

    try:
        if not code or state not in oauth_states:
            return RedirectResponse(f"{FRONTEND_URL}?gmail=error")

        oauth_states.discard(state)

        flow=google_flow()
        flow.fetch_token(code=code)

        gmail_credentials=flow.credentials
        save_gmail_credentials(gmail_credentials)

        return RedirectResponse(f"{FRONTEND_URL}?gmail=connected")

    except Exception as e:
        print("Google OAuth error:",e)
        return RedirectResponse(f"{FRONTEND_URL}?gmail=error")

def gmail_service():
    global gmail_credentials

    if not gmail_credentials:
        gmail_credentials=load_gmail_credentials()

    if not gmail_credentials:
        raise RuntimeError("Gmail is not connected.")

    if gmail_credentials.expired and gmail_credentials.refresh_token:
        gmail_credentials.refresh(Request())
        save_gmail_credentials(gmail_credentials)

    return build(
        "gmail",
        "v1",
        credentials=gmail_credentials,
        cache_discovery=False
    )

@app.get("/api/gmail/status")
def gmail_status():
    try:
        service=gmail_service()
        profile=service.users().getProfile(userId="me").execute()

        return {
            "success":True,
            "connected":True,
            "email":profile.get("emailAddress"),
            "messages_total":profile.get("messagesTotal",0),
            "threads_total":profile.get("threadsTotal",0)
        }

    except Exception as e:
        print("Gmail status error:",e)
        return {"success":True,"connected":False}

@app.post("/api/gmail/disconnect")
def gmail_disconnect():
    global gmail_credentials
    gmail_credentials=None
    delete_gmail_credentials()
    return {"success":True,"connected":False}

# =========================
# GMAIL MESSAGES
# =========================

@app.get("/api/gmail/messages")
def gmail_messages(max_results:int=20,page_token:str=None):
    try:
        max_results=max(1,min(max_results,100))
        service=gmail_service()

        args={
            "userId":"me",
            "maxResults":max_results
        }

        if page_token:
            args["pageToken"]=page_token

        data=service.users().messages().list(**args).execute()

        messages=[]

        for item in data.get("messages",[]):
            message_id=item.get("id")

            message=service.users().messages().get(
                userId="me",
                id=message_id,
                format="metadata",
                metadataHeaders=[
                    "From","To","Subject","Date","Reply-To"
                ]
            ).execute()

            headers={
                h["name"].lower():h["value"]
                for h in message.get("payload",{}).get("headers",[])
            }

            messages.append({
                "id":message_id,
                "thread_id":message.get("threadId"),
                "sender":headers.get("from","Unknown"),
                "recipient":headers.get("to","Unknown"),
                "reply_to":headers.get("reply-to","Not specified"),
                "subject":headers.get("subject","No Subject"),
                "date":headers.get("date","Unknown"),
                "snippet":message.get("snippet",""),
                "label_ids":message.get("labelIds",[])
            })

        return {
            "success":True,
            "messages":messages,
            "next_page_token":data.get("nextPageToken")
        }

    except Exception as e:
        print("Gmail messages error:",e)
        return {"success":False,"error":str(e)}

# =========================
# GMAIL ANALYSIS
# =========================

def decode_gmail_raw(raw):
    padding="="*((-len(raw))%4)
    return base64.urlsafe_b64decode(raw+padding)

@app.get("/api/gmail/analyze/{message_id}")
async def analyze_gmail(message_id:str):
    try:
        service=gmail_service()

        message=service.users().messages().get(
            userId="me",
            id=message_id,
            format="raw"
        ).execute()

        raw=message.get("raw")

        if not raw:
            return {
                "success":False,
                "error":"Gmail returned an empty email."
            }

        email_bytes=decode_gmail_raw(raw)

        result=await analyze_bytes(
            email_bytes,
            f"gmail_{message_id}.eml"
        )

        if result.get("success"):
            result["source_type"]="GMAIL"
            result["email"]["gmail_message_id"]=message_id
            result["email"]["gmail_thread_id"]=message.get("threadId")

        return result

    except Exception as e:
        print("Gmail analysis error:",e)
        return {"success":False,"error":str(e)}

# =========================
# SERVER
# =========================

if __name__=="__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT","8000"))
    )