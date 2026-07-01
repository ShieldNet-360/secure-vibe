# Fixture: ANTI-PATTERN.
# AWS / GCP / Azure expose cloud-metadata services at well-known
# link-local addresses (169.254.169.254 on IPv4, fd00:ec2::254 on IPv6
# for AWS). A successful SSRF that reaches them yields temporary IAM
# credentials. See https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
# and skills/ssrf-prevention/rules/cloud_metadata_endpoints.json.
import requests


def fetch_remote(host: str) -> str:
    # BAD: caller-supplied host with no allow-list. Attacker passes
    # host='169.254.169.254' or even host='metadata.google.internal'.
    return requests.get(f"http://{host}/latest/meta-data/", timeout=2).text


METADATA_BLOCKLIST = {
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.azure.com",
}


def fetch_remote_safe(host: str) -> str:
    if host in METADATA_BLOCKLIST:
        raise ValueError("metadata endpoints are not allowed")
    return requests.get(f"http://{host}/", timeout=2).text
