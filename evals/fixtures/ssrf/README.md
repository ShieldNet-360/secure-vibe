# `evals/fixtures/ssrf`

Server-Side Request Forgery anti-patterns. The harness either runs
the `ssrf-prevention` skill's static rules over each file or feeds
the file to an agent and grades whether the agent identifies the
same sink.

Each fixture cites:

- The vulnerable sink (e.g. `requests.get(user_supplied_url)`).
- The source rule in `skills/ssrf-prevention/rules/ssrf_sinks.json`
  or `skills/ssrf-prevention/rules/cloud_metadata_endpoints.json`
  that catches it.

Seed fixtures:

| File | Anti-pattern | Source rule |
| --- | --- | --- |
| `user-url-passthrough.py` | flask handler proxies arbitrary user URLs | `skills/ssrf-prevention/rules/ssrf_sinks.json` |
| `metadata-endpoint.py` | URL not blocked from hitting cloud metadata IPs (169.254.169.254 / fd00:ec2::254) | `skills/ssrf-prevention/rules/cloud_metadata_endpoints.json` |
