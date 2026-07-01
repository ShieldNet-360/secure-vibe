# Multi-stage: USER root only in the builder stage. The AST pass
# should suppress dkr-non-root-user on the final stage.
FROM golang:1.22-bookworm AS builder
USER root
WORKDIR /src
COPY . .
RUN go build -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot@sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f AS final
COPY --from=builder /out/app /app
USER 10001
ENTRYPOINT ["/app"]
