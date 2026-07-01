# Fixture: no-healthcheck.Dockerfile
#
# The container-security checklist requires a HEALTHCHECK on long-
# running services (dkr-healthcheck-defined). The Go-side scanner
# does not currently implement that check, so this fixture has zero
# expected findings: it serves as a control to confirm the scanner
# does not regress and start emitting spurious findings before a
# HEALTHCHECK rule is reviewed in, and as a placeholder for when
# that rule is added.
FROM nginx:1.27.0@sha256:0000000000000000000000000000000000000000000000000000000000000000
USER 10001
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
