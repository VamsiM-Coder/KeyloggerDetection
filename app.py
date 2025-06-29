import streamlit as st
from cryptography.fernet import Fernet
import re
import requests
import json
import tempfile
import os
from PIL import Image
import base64
import io

# ========== CONFIG (replace with your actual keys) ==========
VIRUSTOTAL_API_KEY = "Enter your API Key"
ABUSEIPDB_API_KEY = "Enter your API Key"
PERSPECTIVE_API_KEY = "Enter your API Key"
# ============================================================

# ===== DECRYPTION =====
def decrypt_fernet_file(file, key):
    try:
        fernet = Fernet(key.encode())
        encrypted = file.read()
        decrypted = fernet.decrypt(encrypted)
        return decrypted
    except Exception as e:
        return f"[ERROR] Decryption failed: {str(e)}"

# ===== REGEX SCAN =====
patterns = {
    "ip_addresses": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "ipv6_pattern": r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:|\b:(?::[A-Fa-f0-9]{1,4}){1,7}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}\b",
    "mac_addresses": r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
    "dns_addresses": r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
    "credit_cards": r'\b(?:\d[ -]*?){13,16}\b',
    "ssns": r'\d{3}-\d{2}-\d{4}',
    "emails": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "urls": r'https?://[^\s]+',
    "phone_numbers": r'\b(?:\+?(\d{1,3})[-.●]?)?(\d{3})[-.●]?(\d{3})[-.●]?(\d{4})\b',
    "pin_codes": r'\b\d{4,6}\b',
    "password": r"(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=*!?])[A-Za-z\d@#$%^&+=*!?]{8,}",
    "api_keys": r'\b(AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,34}|AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36})\b',
    "api_key": r"\b(?:[A-Za-z0-9_\-]{32,45}={0,2}|[A-Fa-f0-9]{64,128})\b",
    "sql_injection": r'(?i)\b(select|union|insert|update|delete|drop|truncate|alter|create|grant|revoke)\b.*?(--|\bfrom\b|\bwhere\b|\binto\b|\bvalues\b|\btable\b|\bjoin\b|\border\b|\bgroup\b|\bhaving\b)',
    "fernet_key": r"\b[A-Za-z0-9_-]{43}=\b",
    "hex_api_key": r"\b[A-Fa-f0-9]{64,128}\b"
}

harmful_keywords = [
    "hack", "hacking", "phishing", "malware", "steal", "exploit", "ransomware", "ddos","malicious",
    "sql injection", "xss", "keylogger", "rootkit", "trojan", "virus", "spyware", "adware",
    "breach", "zero-day", "backdoor", "botnet", "attack", "credential stuffing", "data leak",
    "brute force", "password cracking", "dark web", "blackhat", "spoofing", "session hijack",
    "social engineering", "rm -rf", "kill", "extort", "encryption", "decrypt", "payload",
    "infect", "vulnerability", "penetration", "cyberattack", "rat", "remote access trojan",
    "DROP TABLE", "DELETE FROM", "SELECT *", "INSERT INTO", "credit card", "bank account",
    "SSN", "PIN code", "netcat", "nmap", "remote shell", "encryption key", "private key",
    "authentication token", "session ID", "classified", "access token", "secret key",
    "bearer token", "sqlmap", "etc/passwd", "telnet", "ftp", "ssh", "reverse shell",
    "CVE-", "rootkit", "payload", "IFSC code", "routing number", "SWIFT code", "GDPR",
    "HIPAA", "PII", "privacy breach", "bitcoin address", "crypto wallet", "monero",
    "unauthorized access", "sudo", "chmod", "curl", "wget", "powershell", "packet sniffing",
    "script execution", "http://", "https://", ".onion", "tor network", "SSL certificate",
    "OAuth token", "internal use only", "verify your account", "reset your password","login","credentials","leak","password"
]

def regex_threat_scan(text):
    findings = {}
    
    # Apply regex patterns to extract potential threats
    for label, pattern in patterns.items():
        findings[label] = re.findall(pattern, text)

    # Match harmful keywords
    findings['keywords'] = [kw for kw in harmful_keywords if kw.lower() in text.lower()]

    # AbuseIPDB IP analysis
    ip_addresses = re.findall(patterns['ip_addresses'], text)
    if ip_addresses:
        for ip in ip_addresses:
            try:
                url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
                headers = {
                    'Key': ABUSEIPDB_API_KEY,
                    'Accept': 'application/json'
                }
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    details = [
                        f"IP Address: {ip}",
                        f"Country: {data.get('countryCode', 'N/A')}",
                        f"Domain: {data.get('domain', 'N/A')}",
                    ]
                    formatted = "\n".join(details)
                    findings.setdefault('abuseipdb', []).append(formatted)
            except Exception as e:
                print(f"Error fetching AbuseIPDB data for IP {ip}: {str(e)}")

    # VirusTotal URL analysis
    urls = findings.get('urls', [])
    if urls:
        for url in urls[:3]:  # Limit to 3 to avoid API quota issues
            try:
                vt_result = check_virustotal_url(url)
                findings.setdefault('virustotal', []).append({url: vt_result})
            except Exception as e:
                print(f"Error fetching VirusTotal data for URL {url}: {str(e)}")

    return findings

def perspective_score(text):
    url = f"https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze?key={PERSPECTIVE_API_KEY}"
    data = {
        'comment': {'text': text},
        'languages': ['en'],
        'requestedAttributes': {'TOXICITY': {}, 'THREAT': {}, 'INSULT': {}}
    }
    r = requests.post(url, json=data)
    return r.json()['attributeScores'] if r.status_code == 200 else None

def check_virustotal_url(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    scan_url = f"https://www.virustotal.com/api/v3/urls"
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    report_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    
    response = requests.get(report_url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return stats
    else:
        return {"error": f"Failed to fetch VirusTotal data for URL: {url}"}


# ===== STREAMLIT UI =====
st.title("Advanced Keylogger Threat Detection System")

# === MANUAL TEXT THREAT ANALYSIS ===
st.header("📝 Manual Threat Text Analysis")
user_input = st.text_area("Paste or write text to analyze for threats")
if st.button("Analyze Text") and user_input:
    results = regex_threat_scan(user_input)
    for k, v in results.items():
        if v:
            st.warning(f"{k.replace('_',' ').title()} Detected: {v if len(v)<10 else v[:10]+['...']}")

    score = perspective_score(user_input[:3000])
    if score:
        for k, v in score.items():
            st.write(f"{k}: {v['summaryScore']['value']:.2f}")

# === TEXT FILE DECRYPTION ===
st.header("📄 Decrypt & Analyze Encrypted Text")
key = st.text_input("Enter Decryption Key", type="password")
enc_file = st.file_uploader("Upload Encrypted Text File (.enc)", type=["enc"], key="text")
if st.button("Decrypt & Analyze Text File") and key and enc_file:
    decrypted = decrypt_fernet_file(enc_file, key)
    if isinstance(decrypted, bytes):
        text = decrypted.decode(errors="ignore")
        st.success("Text File Decryption Successful!")
        st.code(text[:1000] + ("..." if len(text) > 1000 else ""))
        results = regex_threat_scan(text)
        for k, v in results.items():
            if v:
                st.warning(f"{k.replace('_',' ').title()} Detected: {v if len(v)<10 else v[:10]+['...']}")
        score = perspective_score(text[:3000])
        if score:
            for k, v in score.items():
                st.write(f"{k}: {v['summaryScore']['value']:.2f}")
    else:
        st.error(decrypted)

# === SCREENSHOT DECRYPTION ===
st.header("🖼 Decrypt Encrypted Screenshot")
screenshot_file = st.file_uploader("Upload Encrypted Screenshot (.enc)", type="enc", key="screenshot")
if st.button("Decrypt Screenshot") and screenshot_file and key:
    image_bytes = decrypt_fernet_file(screenshot_file, key)
    if isinstance(image_bytes, bytes):
        image = Image.open(io.BytesIO(image_bytes))
        st.image(image, caption="Decrypted Screenshot")

        # Convert image to downloadable bytes
        buffered = io.BytesIO()
        image.save(buffered, format="PNG")
        img_data = buffered.getvalue()
        
        # Add download button
        st.download_button(
            label="📥 Download Screenshot",
            data=img_data,
            file_name="decrypted_screenshot.png",
            mime="image/png"
        )
    else:
        st.error(image_bytes)


# === SCREEN RECORDING DECRYPTION ===
st.header("🎥 Decrypt Encrypted Screen Recording")
screenrec_file = st.file_uploader("Upload Encrypted Screen Recording (.enc)", type="enc", key="screenrec")
if st.button("Decrypt Screen Recording") and screenrec_file and key:
    video_bytes = decrypt_fernet_file(screenrec_file, key)
    if isinstance(video_bytes, bytes):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as tmp_file:
            tmp_file.write(video_bytes)
            tmp_file_path = tmp_file.name
        st.success("Screen Recording Decryption Successful!")
        with open(tmp_file_path, "rb") as f:
            st.download_button("📥 Download Video", data=f, file_name="decrypted_recording.mp4", mime="video/mp4")
    else:
        st.error(video_bytes)
st.markdown("---")
st.caption("✅ DEVELOPED BY PROJECT TEAM-1")