# ARG-substituted FROM: scanner should resolve the ARG default and
# flag dkr-explicit-latest-tag against the resolved value.
ARG BASE_IMAGE=node:latest
FROM $BASE_IMAGE AS final
USER 10001
ENTRYPOINT ["/usr/local/bin/node", "app.js"]
