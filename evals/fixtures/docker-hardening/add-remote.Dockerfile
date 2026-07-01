# Fixture: add-remote.Dockerfile
#
# Uses `ADD https://...` to pull a remote tarball at build time
# instead of `RUN curl --fail <url> && sha256sum -c`. The scanner's
# dkr-no-add-remote rule flags any `ADD http(s)://...` line.
FROM debian:12-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000
USER 10001
WORKDIR /opt/tool
ADD https://example.com/releases/tool.tar.gz /opt/tool/tool.tar.gz
RUN tar -xzf tool.tar.gz
CMD ["/opt/tool/tool"]
