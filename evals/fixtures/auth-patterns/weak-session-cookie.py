# Fixture: ANTI-PATTERN.
# Setting a session cookie without HttpOnly / Secure / SameSite makes
# it readable from JS (XSS exfil), shippable over plaintext HTTP, and
# eligible for cross-site requests. See OWASP Session Management
# Cheat Sheet and skills/auth-security/SKILL.md (session section).
from flask import Flask, make_response

app = Flask(__name__)


@app.post("/login")
def login_bad():
    resp = make_response("ok")
    # BAD: missing httponly, secure, samesite — all three default to None.
    resp.set_cookie("session", "<server-issued>")
    return resp


@app.post("/login-safe")
def login_safe():
    resp = make_response("ok")
    resp.set_cookie(
        "session",
        "<server-issued>",
        httponly=True,
        secure=True,
        samesite="Lax",
    )
    return resp
