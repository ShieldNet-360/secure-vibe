// Fixture: ANTI-PATTERN.
// Single-page apps must NOT use the OAuth 2.0 Implicit Flow
// (response_type=token). RFC 9700 (OAuth 2.0 Security BCP) removes
// it; SPAs should use Authorization Code with PKCE instead.
// See skills/auth-security/rules/oauth_flows.json and
// https://datatracker.ietf.org/doc/html/rfc9700.

const AUTH_URL = "https://issuer.example.com/oauth2/authorize";

function login() {
  // BAD: response_type=token returns the access token in the URL
  // fragment, where it leaks via browser history, referer headers,
  // and any third-party JS on the page.
  const u = new URL(AUTH_URL);
  u.searchParams.set("response_type", "token");
  u.searchParams.set("client_id", "spa-client");
  u.searchParams.set("redirect_uri", "https://spa.example.com/cb");
  u.searchParams.set("scope", "openid profile");
  window.location.href = u.toString();
}

// Correct: Authorization Code with PKCE.
function loginSafe() {
  const u = new URL(AUTH_URL);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", "spa-client");
  u.searchParams.set("redirect_uri", "https://spa.example.com/cb");
  u.searchParams.set("scope", "openid profile");
  u.searchParams.set("code_challenge", "<pkce-challenge>");
  u.searchParams.set("code_challenge_method", "S256");
  window.location.href = u.toString();
}
