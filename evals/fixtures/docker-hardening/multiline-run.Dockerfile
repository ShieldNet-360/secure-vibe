# curl | sh split across a backslash continuation.
FROM debian:bookworm-slim@sha256:99ce2cfaa6ca7b5e8b1c0a13a78f827bbac6f3e3b6d0d24a3e8c4f2a0e8c5b9c AS final
RUN apt-get update \
 && curl -fsSL https://example.com/install.sh \
    | sh \
 && rm -rf /var/lib/apt/lists/*
USER 10001
