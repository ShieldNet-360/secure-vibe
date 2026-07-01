---
id: file-upload-security
version: "1.0.0"
title: "File Upload Security"
description: "Validate user uploads: MIME magic bytes, filename sanitization, size limits, separate serving domain, AV scanning, polyglot detection"
category: prevention
severity: high
applies_to:
  - "when generating an HTTP file-upload endpoint"
  - "when wiring presigned-URL upload to S3 / GCS / Azure Blob"
  - "when adding image/PDF/document processing of user uploads"
  - "when reviewing user-generated-content storage and serving"
languages: ["*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "ssrf-prevention", "container-security", "cors-security"]
last_updated: "2026-06-20"
sources:
  - "OWASP File Upload Cheat Sheet"
  - "CWE-434: Unrestricted Upload of File with Dangerous Type"
  - "CWE-22: Path Traversal"
  - "CVE-2018-15473 (libmagic), CVE-2016-3714 (ImageTragick)"
---

# File Upload Security

## Rules (for AI agents)

### ALWAYS
- Verify **magic bytes** of every upload server-side. `Content-Type`
  and file extension are attacker-controlled and never sufficient.
  Use libmagic, `file-type` (Node), `mimetypes-magic` (Python),
  or Tika.
- Maintain an **allowlist** of accepted types per endpoint
  (`image/png`, `image/jpeg`, `application/pdf`, …). Deny everything
  else, including `text/html`, `image/svg+xml` (carries `<script>`),
  `text/xml`, and `application/octet-stream`.
- Sanitize filenames: strip directory components, normalize Unicode,
  reject `..`, NUL byte, control chars, reserved Windows names
  (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`), and any non
  `[a-zA-Z0-9._-]` characters. Store as a UUID / hash and keep the
  original filename in a separate, escaped metadata column.
- Enforce a **size limit** at the proxy / API gateway *and* at the
  application — at least double-layer. The proxy limit prevents
  bandwidth DoS; the app limit prevents memory exhaustion when a
  proxy is misconfigured.
- Store uploads **outside the document root** and serve them from a
  separate domain (`usercontent.example.net`) on a CDN. Set
  `Content-Disposition: attachment` for non-image types and a
  `Content-Security-Policy: default-src 'none'; sandbox` header to
  neutralize any inline-rendered HTML/SVG.
- Run a **virus scanner** (ClamAV, VirusTotal, Sophos) on every
  upload before making it accessible to other users — out of band so
  the request itself isn't latency-bound.
- Re-encode media server-side: `convert in.jpg out.jpg` (ImageMagick
  with a strict `policy.xml`), `ffmpeg -i` for video, `pdftocairo`
  for PDFs. Re-encoding strips most polyglot / steganographic
  payloads and exotic codec exploits.
- For SVG specifically: either render server-side to a raster format,
  or pass through a strict allowlist sanitizer (DOMPurify in Node,
  `lxml.html.clean` in Python) that strips `<script>`, `<iframe>`,
  `<foreignObject>`, `xlink:href` with `javascript:`, and CSS
  expression / url() with non-data URIs.

### NEVER
- Trust `Content-Type` from the client. The mime sniffer in IE / older
  Chrome reads the body for type clues — an HTML payload disguised as
  `image/png` will run as HTML when served same-origin.
- Construct the storage path with the user-supplied filename. Path
  traversal (`../../etc/passwd`) and the Windows reserved-name class
  both reduce to "let attacker pick where to write."
- Serve uploads from the same origin as the application. Serving on
  `api.example.com/uploads/x.html` means a malicious HTML upload runs
  with full access to api.example.com cookies and CORS.
- Use a stack that processes uploads with ImageMagick / libraw /
  ExifTool / ffmpeg without strict policy.xml / sandbox / version
  control. ImageTragick (CVE-2016-3714) and GitLab ExifTool
  (CVE-2021-22205) both relied on a server happily handing
  user-controlled bytes to a media library.
- Allow PDF upload + render in-browser without verifying the PDF
  passes structural validation (e.g. `pdfinfo`). Malicious PDFs are
  a common JavaScript-in-PDF / XFA RCE primitive against Adobe Reader
  on the recipient side, even when the server is safe.
- Use `.docx` / `.xlsx` / `.zip` extraction with `unzip` or
  `python -m zipfile` without a path-traversal-safe extractor.
  Zip slip (CVE-2018-1002201) extracted files outside the target
  directory through `../` entries.
- Use S3 / GCS presigned upload URLs without a strict `Content-Type`
  signed condition and a fixed object-key prefix. Without the
  conditions, the client can upload anything to any key.

### KNOWN FALSE POSITIVES
- Internal-only admin uploads (e.g. an ops dashboard) may legitimately
  trust file extension because the trust boundary is the SSO + IP
  allowlist. Document this as a deliberate decision in the endpoint.
- Some integrations (e.g. exporting CSV from BI tools) need to round-trip
  user-supplied filenames; preserve them in metadata, but the on-disk
  name must still be a UUID.
- Tarballs / DEBs / RPMs in a build pipeline don't need AV scan — the
  trust boundary is the build pipeline's signing key, not the AV.

## Context (for humans)

File upload is the persistent rich-target attack surface. Every
real-world breach lab includes a "find an upload form" early-game
move because the path from upload to RCE is usually short: upload an
HTML file with a JavaScript credential stealer, upload a PHP / JSP
shell to a misconfigured doc-root, upload an SVG with a
SAML-stealer `<script>`, upload an EXIF-payloaded image to a
vulnerable ImageMagick service.

The defenses are well-understood and inexpensive — the bug is that
they have to be applied in combination. A magic-byte allowlist is
trivially bypassed by a polyglot (a file that is simultaneously a
valid PNG and a valid HTML page). A separate serving domain
neutralizes the polyglot's HTML execution. A virus scanner catches
known malware. Re-encoding strips weird codec payloads. Each defense
is a layer; missing one layer turns most uploads from "stored data"
into "stored RCE."


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (probe the suspect endpoint).** POST a payload the allowlist should reject and watch where it lands: a `shell.php`/`shell.jsp` with a real magic-byte mismatch, an `image/png` content-type wrapping HTML/SVG-with-`<script>`, or a filename like `../../shell.php`. Real if the upload is accepted *and* the stored object is reachable from an executable/same-origin path, the traversal escapes the upload dir, or the SVG/HTML renders script when fetched. False positive if magic bytes are verified server-side, the name is replaced with a UUID, and the file serves from a separate sandboxed domain as `attachment` — the probe is rejected or served inert.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call): feed the validator the disallowed cases and assert each is rejected — `.php`/`.jsp`/`.svg`/`.html` extensions, spoofed `Content-Type` whose magic bytes don't match, oversize body past the limit, and a `../../` / NUL / reserved-name filename (assert the on-disk key is a sanitized UUID, never the input). Then assert a benign `image/png` with valid magic bytes still uploads and serves. Commit it to CI so the guard can't be silently dropped in a later refactor.

## References

- `rules/upload_validation.json`
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
- [CWE-434](https://cwe.mitre.org/data/definitions/434.html).
- [CWE-22 (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html).
- [Snyk Zip Slip directory](https://snyk.io/research/zip-slip-vulnerability).
- [ImageTragick (CVE-2016-3714)](https://imagetragick.com/).
