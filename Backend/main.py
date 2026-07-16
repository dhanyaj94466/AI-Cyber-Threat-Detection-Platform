
from config import API_KEY
import base64
import socket
import ssl
import requests
import feedparser
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email_config import EMAIL, PASSWORD, RECEIVER
from urllib.parse import urlparse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
print("THIS IS MY MAIN.PY")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Allow frontend to access backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/virustotal")
def virus_total(url: str):

    try:

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        headers = {
            "x-apikey": API_KEY
        }

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers
        )

        if response.status_code != 200:

            return {
                "error": "URL not found in VirusTotal. Please scan it manually first or try another URL."
            }

        data = response.json()["data"]["attributes"]["last_analysis_stats"]

        malicious = data["malicious"]
        suspicious = data["suspicious"]
        harmless = data["harmless"]
        undetected = data["undetected"]

        if malicious == 0 and suspicious == 0:
            verdict = "✅ Safe"
        elif malicious < 5:
            verdict = "⚠ Suspicious"
        else:
            verdict = "❌ Malicious"

        return {

            "malicious": malicious,

            "suspicious": suspicious,

            "harmless": harmless,

            "undetected": undetected,

            "verdict": verdict

        }
    
    

    except Exception as e:

        return {

            "error": str(e)

        }
    

    
@app.get("/scan")
def scan(url: str):

    try:

        response = requests.get(url, timeout=8)

        parsed = urlparse(url)

        domain = parsed.netloc

        ip = socket.gethostbyname(domain)

        headers = response.headers

        https = url.startswith("https")

        score = 100

        checks = []

        if "Content-Security-Policy" in headers:
            checks.append("✅ Content Security Policy")
        else:
            checks.append("❌ Content Security Policy Missing")
            score -= 10

        if "Strict-Transport-Security" in headers:
            checks.append("✅ HSTS")
        else:
            checks.append("❌ HSTS Missing")
            score -= 10

        if "X-Frame-Options" in headers:
            checks.append("✅ X-Frame-Options")
        else:
            checks.append("❌ X-Frame-Options Missing")
            score -= 10

        if "X-Content-Type-Options" in headers:
            checks.append("✅ X-Content-Type-Options")
        else:
            checks.append("❌ X-Content-Type-Options Missing")
            score -= 10

        if score >= 90:
            level = "🟢 Low"

        elif score >= 70:
            level = "🟡 Medium"

        elif score >= 50:
            level = "🟠 High"

        else:
            level = "🔴 Critical"

        return {

            "status": response.status_code,

            "domain": domain,

            "ip": ip,

            "https": https,

            "score": score,

            "level": level,

            "headers": checks

        }

    except Exception as e:

        return {

            "error": str(e)

        }


@app.get("/ipinfo")
def ipinfo(ip: str):

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip}"
        )

        data = response.json()

        return {

            "ip": ip,

            "country": data.get("country"),

            "city": data.get("city"),

            "isp": data.get("isp"),

            "organization": data.get("org"),

            "status": data.get("status")

        }

    except Exception as e:

        return {

            "error": str(e)

        }
        

# ===============================
# News Function
# ===============================

        
import requests

NEWS_API_KEY = "3d9337aaae3c474eab4718e0c4074f19"

@app.get("/news")
def get_news():

    feed = feedparser.parse(
        "https://www.bleepingcomputer.com/feed/"
    )

    news = []

    for article in feed.entries[:10]:

        title = article.title

        source = "BleepingComputer"

        published = article.published[:16]

        url = article.link

        severity = "Low"

        title_lower = title.lower()

        if "critical" in title_lower or "zero-day" in title_lower:
            severity = "Critical"

        elif "ransomware" in title_lower or "malware" in title_lower:
            severity = "High"

        elif "vulnerability" in title_lower or "exploit" in title_lower:
            severity = "Medium"

        news.append({

            "title": title,

            "source": source,

            "published": published,

            "severity": severity,

            "url": url

        })

    return {
        "news": news
    }

# ===============================
# Send Email Function
# ===============================

def send_email(ip, attempts):

    try:

        subject = "Critical Threat Detected"

        body = f"""
Critical Threat Detected

IP Address: {ip}

Failed Attempts: {attempts}

Attack Type: Brute Force Attack

Recommendation:
Block this IP immediately.
"""

        message = MIMEMultipart()

        message["From"] = EMAIL
        message["To"] = RECEIVER
        message["Subject"] = subject

        message.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP("smtp.gmail.com", 587)

        server.starttls()

        server.login(EMAIL, PASSWORD)

        server.sendmail(
            EMAIL,
            RECEIVER,
            message.as_string()
        )

        server.quit()

        return True

    except Exception as e:

        print(e)

        return False


# ===============================
# Email Alert API
# ===============================

@app.get("/send_alert")
def send_alert(ip: str, attempts: int):

    success = send_email(ip, attempts)

    if success:

        return {
            "status": "success",
            "message": "Email alert sent successfully."
        }

    return {
        "status": "error",
        "message": "Failed to send email."
    }


# ===============================
# Home API
# ===============================

@app.get("/")
def home():
    return {
        "message": "Welcome to AI Cyber Threat Detection Platform"
    }
        
@app.get("/test123")
def test123():
    return {
        "message": "Test API Working"
    }
