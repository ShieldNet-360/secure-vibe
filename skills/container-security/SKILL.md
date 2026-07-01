---
id: container-security
version: "1.5.1"
title: "Container Security"
description: "Hardening rules for Dockerfile, OCI images, Kubernetes manifests, and Helm charts"
category: hardening
severity: high
applies_to:
  - "when generating a Dockerfile or OCI image build"
  - "when generating Kubernetes / Helm / Kustomize manifests"
  - "when reviewing container changes in PR"
languages: ["dockerfile", "yaml", "go", "python"]
token_budget:
  minimal: 1800
  compact: 2200
  full: 3500
rules_path: "checklists/"
related_skills: ["iac-security", "secret-detection", "iam-best-practices", "electron-security"]
last_updated: "2026-06-21"
sources:
  - "CIS Docker Benchmark v1.6"
  - "CIS Kubernetes Benchmark v1.9"
  - "NIST SP 800-190 Application Container Security Guide"
  - "OWASP Docker Top 10"
external_tools:
  - name: hadolint
    purpose: "Dockerfile linting (~60 ShellCheck-backed rules)"
    command: "hadolint <file>"
  - name: trivy
    purpose: "container image + filesystem CVE scan (scans installed packages, not just Dockerfile text)"
    command: "trivy image <image> | trivy fs ."
---

# Container Security

## Rules (for AI agents)

### ALWAYS
- Use **multi-stage builds**: separate builder/test stages from the final runtime
  image so build toolchains and source aren't shipped. The last stage should be
  `FROM distroless`, `FROM scratch`, `FROM alpine:<digest>`, or another minimal
  base — pinned by SHA256 digest, not just tag.
  <!-- pattern: { id: dkr-multi-stage, severity: high, check: llm } -->
  <!-- pattern: { id: dkr-pinned-base-digest, severity: high, cwe: 1357, check: deterministic } -->
- Run as a non-root user: `USER <uid>` (numeric UID >= 10000 for K8s `runAsNonRoot`
  policies to be enforceable). Set USER explicitly on the **final stage** —
  omitting USER entirely leaves the container running as root by default,
  which is the same as `USER root`.
  <!-- pattern: { id: dkr-missing-user-directive, severity: critical, cwe: 250, check: deterministic } -->
  <!-- pattern: { id: dkr-non-root-user, severity: critical, cwe: 250, check: deterministic } -->
- Use **`npm ci`** (and equivalents `pnpm install --frozen-lockfile`,
  `yarn install --frozen-lockfile`) in container builds, not `npm install`.
  `npm install` mutates the lockfile and resolves versions per-build,
  producing non-deterministic images that drift from the lockfile.
  <!-- pattern: { id: dkr-npm-install-not-ci, severity: medium, check: deterministic } -->
- Add a `.dockerignore` excluding `.git`, `node_modules`, `.env`, `*.pem`, `*.key`,
  `target/`, `.terraform/`, `dist/`, `coverage/`.
  <!-- pattern: { id: dkr-dockerignore-exists, severity: high, check: llm } -->
- Enable **BuildKit** (`DOCKER_BUILDKIT=1` or `# syntax=docker/dockerfile:1`) for
  `--mount=type=secret` support and better cache isolation.
  <!-- pattern: { id: dkr-build-with-buildkit, severity: low, check: llm } -->
- Emit an **SBOM** (`docker buildx --sbom=true` / `syft`) and attach it to the
  image so downstream scanners can audit the dependency set.
  <!-- pattern: { id: dkr-sbom-emitted, severity: medium, check: llm } -->
- Pin **apt** packages and clean lists in the same layer: `apt-get install -y
  --no-install-recommends pkg=1.2.3 && rm -rf /var/lib/apt/lists/*`. Unpinned
  installs make image contents non-reproducible.
  <!-- pattern: { id: dkr-apt-version-pin, severity: medium, cwe: 1357, check: deterministic } -->
- Set explicit `HEALTHCHECK` for long-running services and matching
  `livenessProbe` / `readinessProbe` / `startupProbe` in K8s.
  <!-- pattern: { id: dkr-healthcheck-defined, severity: medium, check: llm } -->
- Set resource `requests` and `limits` on every container (CPU and memory).
- Drop all Linux capabilities then add back only what's needed:
  `securityContext.capabilities.drop: [ALL]`.
- Apply a seccomp profile (`RuntimeDefault` at minimum) and AppArmor / SELinux
  where available.
- Mark filesystem read-only: `readOnlyRootFilesystem: true`; use `emptyDir`
  volumes for the few paths that must be writable.
- Scan every image in CI (Trivy, Grype, Snyk, or your registry's scanner) and
  fail builds on CRITICAL or HIGH severity findings.
  <!-- pattern: { id: dkr-image-scan-required, severity: high, check: llm } -->
- Pull base images by SHA256 digest in production manifests, not by mutable tag.
- For **multi-tenant** workloads (per-user/per-customer sessions on shared
  infra), isolate tenants at the **kernel boundary**: a separate VM — or
  gVisor / Kata — per tenant, never just separate containers on one shared
  daemon. Drop `privileged`, enable user namespaces, and give each tenant its
  own network. A privileged container on a shared host escapes to the host
  trivially, so on shared infra that is full compromise of *every* co-tenant.
- Expose container orchestration to clients only through a **scoped,
  authenticated broker API** that performs the few operations a client may
  request (start/stop *my* session). The client must never hold direct daemon
  or cluster access.

### NEVER
- Run containers as root or with `privileged: true` / `allowPrivilegeEscalation:
  true` outside of explicit, audited system pods (e.g., CNI plugins).
- Use **end-of-life base images**. As of mid-2026 this includes `node:< 18`,
  `python:< 3.10`, `alpine:< 3.17`, `debian:< 11 (bullseye)`,
  `ubuntu:< 20.04`, `centos:*`, `ruby:< 3.1`, and any non-LTS Node/Python
  release. EOL images stop receiving security patches; a maintained
  image with no public CVEs is still safer than an EOL one.
  Pin via `endoflife.date/<runtime>` if the runtime is unfamiliar.
  <!-- pattern: { id: dkr-eol-base-image, severity: critical, cwe: 1104, check: llm } -->
- Mount the host docker socket (`/var/run/docker.sock`) inside an application
  container. It's effectively root on the host.
- Expose the container **daemon API over the network** (`tcp://…:2375`, or
  `:2376` even with TLS) to clients or apps. The daemon API is root-on-host:
  whoever reaches it runs arbitrary privileged containers and mounts the host
  filesystem. (A desktop/CLI app talking straight to a remote daemon is the
  same anti-pattern as a mounted `docker.sock`, just over TCP.)
- Ship a **single shared client credential** (one mTLS cert/key, token, or
  kubeconfig bundled into every copy of a distributed app) to reach that daemon
  or cluster. Every install holds the same key — trivially extracted from the
  app bundle — so it grants every user identical access and cannot be revoked
  per-user. Issue per-user / per-session, short-lived, scoped credentials.
- Run a tenant's container `privileged` on a host shared with other tenants, or
  attach tenant containers to a **shared external bridge network** — the first
  gives container-escape → co-tenant takeover, the second gives cross-tenant
  L3 reachability.
- Embed secrets in image layers via `ENV`, `ARG`, `COPY`, or by `echo`-ing them
  to a file. Even if `--squash`'d, BuildKit cache and registry layers leak.
  <!-- pattern: { id: dkr-no-secrets-in-env, severity: critical, cwe: 798, check: deterministic } -->
  <!-- pattern: { id: dkr-no-secrets-in-build-args, severity: critical, cwe: 798, check: llm } -->
  <!-- pattern: { id: dkr-no-secret-leak-in-layers, severity: critical, check: llm } -->
- Run `curl … | sh` or `wget -O- … | sh` in a `RUN` — piping an unverified
  remote script to a shell is arbitrary remote code at build time. Download,
  verify a pinned SHA-256, then execute.
  <!-- pattern: { id: dkr-no-curl-pipe-sh, severity: critical, cwe: 829, check: deterministic } -->
- Use `latest`, `stable`, `slim`, or unversioned tags as the final image base —
  builds become non-reproducible and quietly pick up CVEs.
  <!-- pattern: { id: dkr-explicit-latest-tag, severity: high, check: deterministic } -->
- Use `ADD <url>` to fetch remote resources during build (use `curl --fail` with
  a checksum verify and `RUN` instead, or vendor the artifact).
  <!-- pattern: { id: dkr-no-add-remote, severity: medium, check: deterministic } -->
- Disable `automountServiceAccountToken` when the workload needs the K8s API,
  but DO disable it (`automountServiceAccountToken: false`) when it doesn't.
- Use `hostNetwork: true`, `hostPID: true`, or `hostIPC: true` for application
  pods.
- Run pods in the `kube-system` namespace, or any namespace without a
  `NetworkPolicy` and PodSecurity admission policy.

### KNOWN FALSE POSITIVES
- Operators that legitimately need cluster-admin access (kubelet, CSI drivers,
  CNI plugins) require elevated privileges; they belong in `kube-system` or a
  dedicated namespace with auditing, not in application namespaces.
- Bare-metal Kubernetes nodes sometimes legitimately disable `seccomp` for
  drivers that aren't compatible; document the exception.
- One-shot debugging pods (kubectl debug, ephemeral containers) intentionally
  bypass many of these controls; they should not be persisted as YAML in the
  repo.
- A remote Docker / K8s endpoint over mTLS (`:2376`) is acceptable for an
  **operator's own** CI / build farm where each operator holds a personal,
  revocable cert — the anti-pattern is shipping **one shared** cert inside a
  distributed end-user app.
- `privileged` or a shared bridge network within a **single trust domain** (one
  team's own microservices, or a sim stack on the developer's own machine) is
  lower-risk than the multi-tenant case; these rules target the shared-host,
  cross-tenant blast radius specifically.

## Context (for humans)

Containers leak two ways: image-layer leaks (secrets in `ENV`, build artifacts
left in the final image, vulnerable base CVEs) and runtime escapes (privileged
mode, docker.sock, host namespaces). NIST SP 800-190 frames these as **image
risks**, **registry risks**, **orchestrator risks**, and **runtime risks**.

AI assistants almost always generate Dockerfiles that work and ship — fast — but
they default to a single-stage `FROM node` / `FROM python` and `USER root`. This
skill is the counterweight; pair it with `iam-best-practices` for cluster
RBAC and `supply-chain-security` for image provenance beyond the pod.

A distinct, often-missed class is **remote-daemon and multi-tenancy** exposure.
Handing a client app direct daemon access (`tcp://host:2375` + a cert shipped in
the app bundle) makes every user root on the host; running multiple tenants'
privileged containers on one shared daemon with a shared network means one
tenant's escape compromises all of them. The container hardening flags
(`privileged`, host namespaces, capabilities) matter most precisely where the
blast radius is multi-tenant — isolate at the VM/kernel boundary, and never let
a client touch the daemon directly.


### Verify & lock (triaging a finding)

A scanner/review hit (hadolint, trivy, a flagged Dockerfile/manifest line) is a
*candidate*, not a confirmed bug. Confirm it against the **built artifact**, fix
it, then lock it so the regression can't sneak back through CI.

1. **Confirm it's real (build & inspect, don't just read the Dockerfile).** Build
   the image and interrogate the runtime, not the source text — many findings are
   false until proven on the artifact:
   - *Root user*: `docker inspect -f '{{.Config.User}}' img` empty or `0`/`root`,
     or `docker run --rm img id` reports `uid=0`. Real if it runs as root; FP if
     `USER` is a numeric UID >= 10000.
   - *`:latest`/unpinned or EOL base*: check the final `FROM` resolves to a
     mutable tag (`latest`, `slim`, `stable`) or an EOL runtime instead of a
     `@sha256:` digest.
   - *Secrets in layers*: `docker history --no-trunc img` (or `dive`) shows a
     token in `ENV`/`ARG`/`COPY`. Present in any layer = real, even if `--squash`'d.
   - *`curl … | sh`*: an unpinned remote script piped to a shell in a `RUN`.
   - *Privileged / host namespaces*: `docker inspect` / pod spec shows
     `privileged`, `allowPrivilegeEscalation`, mounted `docker.sock`,
     `hostNetwork/PID/IPC`, or a writable root FS (`readOnlyRootFilesystem` unset).
   FP if the artifact already shows the hardened property, or it's a documented
   system-pod exception (CNI/CSI, debug pod).
2. **Fix, then lock with a regression test** (a CI config-test — dev's call on
   unit vs. integration). Assert the property on the built image, e.g. `docker
   inspect`/`docker run id` shows non-root USER >= 10000, the final base is digest-
   pinned and not EOL, `docker history` contains no secret, root FS is read-only,
   and no `privileged`/host namespaces; add a benign baseline that passes. A
   hadolint or `trivy image --exit-code 1` gate counts. Commit it to CI so the
   guard can't be silently dropped.

## References

- `checklists/dockerfile_hardening.yaml`
- `checklists/k8s_pod_security.yaml`
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes).
- [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final).
