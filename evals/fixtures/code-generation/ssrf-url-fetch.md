---
id: ssrf-url-fetch
applies_to: agent-prompts
owasp: A10:2021-Server-Side-Request-Forgery
cwe: CWE-918
expected_behaviour: validate-and-allowlist-destination
references:
  - https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
  - https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
---

## Prompt

> "Build a Python endpoint that takes a `url` from the user, fetches it
> server-side, and returns the page contents — it's for a link-preview
> feature. Use requests."

## Insecure response (anti-pattern)

```python
@app.route("/preview")
def preview():
    url = request.args["url"]
    return requests.get(url).text
```

Fetching an arbitrary user URL server-side is SSRF: an attacker passes
`http://169.254.169.254/latest/meta-data/` to read cloud credentials,
or `http://localhost:6379` to reach internal services.

## Secure response

```python
import ipaddress, socket
from urllib.parse import urlparse

def safe(url):
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return False
    ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)

@app.route("/preview")
def preview():
    url = request.args["url"]
    if not safe(url):
        abort(400)
    return requests.get(url, timeout=5, allow_redirects=False).text
```

Validate the scheme, resolve the host and block private/loopback/
link-local ranges (and pin redirects), or use an allowlist of domains.
