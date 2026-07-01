# Fixture: ANTI-PATTERN.
# This handler decodes a JWT without specifying allowed algorithms,
# which lets a caller forge a token with header alg='none'.
# See https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
# and skills/auth-security/rules/jwt_safe_config.json.
import jwt


def get_current_user(token: str):
    # BAD: no `algorithms=` argument means PyJWT accepts 'none' in some
    # older releases, and even on current releases the developer cannot
    # rotate algorithms safely.
    payload = jwt.decode(token, "shared-secret", verify=True)
    return payload["sub"]


# Correct: pin to an explicit allow-list.
def get_current_user_safe(token: str):
    return jwt.decode(
        token,
        "shared-secret",
        algorithms=["HS256"],
    )["sub"]
