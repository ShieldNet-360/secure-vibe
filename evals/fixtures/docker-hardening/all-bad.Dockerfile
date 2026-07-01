# Worst-case fixture: should fire every Dockerfile rule.
FROM ubuntu:latest
USER root
ENV API_TOKEN=hunter2
ADD https://example.com/installer.tar.gz /tmp/
RUN curl -fsSL https://example.com/x.sh | sh
RUN apt-get update && apt-get install curl
