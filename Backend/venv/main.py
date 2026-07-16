from config import API_KEY
import base64
import socket
import ssl
import requests
from urllib.parse import urlparse
import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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
@app.get("/")
def home():
    return {
        "message": "Welcome to AI Cyber Threat Detection Platform"
    }