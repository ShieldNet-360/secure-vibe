# Clean fixture: every Dockerfile rule should pass.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f AS final
COPY app /app
USER 10001
ENTRYPOINT ["/app"]
