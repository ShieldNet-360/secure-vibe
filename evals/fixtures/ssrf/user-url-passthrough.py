# Fixture: ANTI-PATTERN.
# Server fetches whatever URL the user supplies. Classic SSRF.
# See OWASP SSRF Cheat Sheet and skills/ssrf-prevention/rules/ssrf_sinks.json.
import requests
from flask import Flask, request

app = Flask(__name__)


@app.get("/proxy")
def proxy_bad():
    url = request.args["url"]
    # BAD: no scheme allow-list, no host allow-list, no resolution
    # to public IP block — the attacker can fetch
    # http://169.254.169.254/latest/meta-data/ to read cloud metadata.
    resp = requests.get(url, timeout=5)
    return resp.text


# Correct: scheme + host allow-list, resolve and verify the IP is public.
ALLOWED_HOSTS = {"api.partner.com", "uploads.partner.com"}


def safe_url(url: str) -> bool:
    from urllib.parse import urlparse
    p = urlparse(url)
    return p.scheme in {"https"} and p.hostname in ALLOWED_HOSTS


@app.get("/proxy-safe")
def proxy_safe():
    url = request.args["url"]
    if not safe_url(url):
        return "blocked", 400
    return requests.get(url, timeout=5).text
