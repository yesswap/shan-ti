"""
Email service — sends verification emails via SMTP.
Works with any SMTP provider: Gmail, Resend, Mailgun, Postmark.
For free tier: Gmail SMTP or Resend free (3000 emails/mo).
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from string import Template

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", "noreply@threatlens.io")
APP_URL = os.getenv("APP_URL", "http://localhost:3000")


def _send(to: str, subject: str, html: str):
    if not SMTP_USER or not SMTP_PASS:
        # Dev mode — just print
        print(f"\n📧 EMAIL TO: {to}\nSUBJECT: {subject}\n(SMTP not configured — set SMTP_USER/SMTP_PASS)\n")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"ThreatLens <{FROM_EMAIL}>"
    msg["To"] = to
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(FROM_EMAIL, to, msg.as_string())


VERIFICATION_HTML = """
<!DOCTYPE html>
<html>
<body style="font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px;">
  <div style="max-width: 520px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; border: 1px solid #334155;">
    <h1 style="color: #38bdf8; font-size: 24px; margin: 0 0 8px;">ThreatLens</h1>
    <p style="color: #94a3b8; margin: 0 0 24px; font-size: 13px;">Threat Actor Intelligence Platform</p>
    <h2 style="font-size: 18px; margin: 0 0 16px;">Verify your email</h2>
    <p style="color: #cbd5e1; line-height: 1.6;">You're one step away from accessing ThreatLens API. Click the button below to verify your email and get your API key.</p>
    <a href="$verify_url" style="display: inline-block; margin: 24px 0; padding: 12px 28px; background: #0ea5e9; color: white; text-decoration: none; border-radius: 8px; font-weight: 600;">
      Verify Email & Get API Key →
    </a>
    <p style="color: #64748b; font-size: 12px; margin-top: 24px;">This link expires in 24 hours. If you didn't sign up, ignore this email.</p>
  </div>
</body>
</html>
"""

API_KEY_HTML = """
<!DOCTYPE html>
<html>
<body style="font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px;">
  <div style="max-width: 520px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; border: 1px solid #334155;">
    <h1 style="color: #38bdf8; font-size: 24px; margin: 0 0 8px;">ThreatLens</h1>
    <p style="color: #94a3b8; margin: 0 0 24px; font-size: 13px;">Threat Actor Intelligence Platform</p>
    <h2 style="font-size: 18px; margin: 0 0 16px;">Your API key is ready</h2>
    <p style="color: #cbd5e1;">Here is your API key. <strong style="color: #f87171;">Save it now — it will not be shown again.</strong></p>
    <div style="background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 16px; margin: 20px 0; font-family: monospace; font-size: 14px; word-break: break-all; color: #34d399;">
      $api_key
    </div>
    <h3 style="font-size: 14px; color: #94a3b8; margin-bottom: 8px;">Quick start</h3>
    <pre style="background: #0f172a; padding: 16px; border-radius: 8px; font-size: 12px; color: #e2e8f0; overflow-x: auto;">curl -H "X-API-Key: $api_key" \\
  $app_url/api/v1/actors</pre>
    <p style="color: #64748b; font-size: 12px; margin-top: 24px;">
      Plan: <strong style="color: #94a3b8;">Free</strong> — 10 req/min · 500 req/day<br>
      Docs: <a href="$app_url/docs" style="color: #38bdf8;">$app_url/docs</a>
    </p>
  </div>
</body>
</html>
"""


def send_verification_email(to: str, token: str):
    verify_url = f"{APP_URL}/api/v1/auth/verify?token={token}"
    html = Template(VERIFICATION_HTML).substitute(verify_url=verify_url)
    _send(to, "Verify your ThreatLens account", html)


def send_api_key_email(to: str, api_key: str):
    html = Template(API_KEY_HTML).substitute(api_key=api_key, app_url=APP_URL)
    _send(to, "Your ThreatLens API key", html)
