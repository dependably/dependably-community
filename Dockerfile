# syntax=docker/dockerfile:1
# Private-registry credentials enter the build only as a BuildKit secret
# (id=registry_key) mounted at /run/secrets/registry_key for the duration of the
# RUN steps that need them — never as an ARG, which would persist in layer
# metadata/history and builder cache. The non-secret REGISTRY_URL stays an ARG.

# Frontend build stage. Pinned to the build platform: the emitted wwwroot assets
# and SBOM are architecture-independent, so this stage runs node/esbuild natively
# on the builder instead of under QEMU emulation for the non-native target arch
# (esbuild's native binary aborts with SIGILL under QEMU).
FROM --platform=$BUILDPLATFORM node:26-alpine@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66 AS frontend
WORKDIR /web
COPY web/package*.json ./
ARG REGISTRY_URL=
# .npmrc (containing the auth token) is written, used, and removed within a single
# RUN so no layer ever contains the credential.
# hadolint ignore=DL4006
RUN --mount=type=secret,id=registry_key \
    if [ -n "$REGISTRY_URL" ] && [ -s /run/secrets/registry_key ]; then \
      HOST=$(printf '%s' "$REGISTRY_URL" | sed -E 's|^https?://||; s|/.*||'); \
      printf 'registry=%s/npm/\n//%s/npm/:_authToken=%s\nfund=false\n' \
        "$REGISTRY_URL" "$HOST" "$(cat /run/secrets/registry_key)" > /root/.npmrc; \
    fi && \
    npm ci && \
    rm -f /root/.npmrc
COPY web/ ./
# hadolint ignore=DL3059
RUN npm run sbom:prod
# hadolint ignore=DL3059
RUN npm run build

# Backend build stage — restore, generate backend SBOM, publish
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine@sha256:5c559aa5d99337e400d39ab4fa1f6979d126c29b20939d53658ed38300571e74 AS build
WORKDIR /src

COPY Dependably.sln .
COPY Directory.Build.props .
COPY src/Dependably/Dependably.csproj src/Dependably/
COPY src/Dependably.Core/Dependably.Core.csproj src/Dependably.Core/
COPY src/Dependably.Management/Dependably.Management.csproj src/Dependably.Management/
ARG TARGETARCH
ARG VERSION=0.1.0
ARG REGISTRY_URL=
# NuGet.Config carries only the (non-secret) source URL. The feed credential is
# surfaced per-step via NuGet's NuGetPackageSourceCredentials_<source> environment
# convention from the secret mount, so it exists only inside each RUN that restores.
RUN if [ -n "$REGISTRY_URL" ]; then \
      { \
        echo '<?xml version="1.0" encoding="utf-8"?>'; \
        echo '<configuration>'; \
        echo '  <packageSources>'; \
        echo '    <clear />'; \
        echo "    <add key=\"dependably\" value=\"${REGISTRY_URL}/nuget/v3/index.json\" />"; \
        echo '  </packageSources>'; \
        echo '</configuration>'; \
      } > /src/NuGet.Config; \
    fi
RUN --mount=type=secret,id=registry_key \
    if [ -s /run/secrets/registry_key ]; then \
      NUGET_CREDS="Username=ci;Password=$(cat /run/secrets/registry_key)"; \
      export NuGetPackageSourceCredentials_dependably="$NUGET_CREDS"; \
    fi && \
    case "$TARGETARCH" in \
      amd64) echo linux-musl-x64 ;; \
      *) echo linux-musl-arm64 ;; \
    esac > /tmp/rid && \
    RID=$(cat /tmp/rid) && \
    dotnet restore src/Dependably/Dependably.csproj -r "$RID"
RUN --mount=type=secret,id=registry_key \
    if [ -s /run/secrets/registry_key ]; then \
      NUGET_CREDS="Username=ci;Password=$(cat /run/secrets/registry_key)"; \
      export NuGetPackageSourceCredentials_dependably="$NUGET_CREDS"; \
    fi && \
    dotnet tool install CycloneDX --tool-path /tools && \
    /tools/dotnet-CycloneDX src/Dependably/Dependably.csproj \
        -o /sboms -fn sbom-backend.json -F json -spv 1.6 \
        --exclude-dev

COPY src/Dependably/ src/Dependably/
COPY src/Dependably.Core/ src/Dependably.Core/
COPY src/Dependably.Management/ src/Dependably.Management/
COPY skills/ skills/
COPY --from=frontend /src/Dependably.Management/wwwroot/ src/Dependably.Management/wwwroot/
RUN --mount=type=secret,id=registry_key \
    if [ -s /run/secrets/registry_key ]; then \
      NUGET_CREDS="Username=ci;Password=$(cat /run/secrets/registry_key)"; \
      export NuGetPackageSourceCredentials_dependably="$NUGET_CREDS"; \
    fi && \
    RID=$(cat /tmp/rid) && \
    dotnet publish src/Dependably/Dependably.csproj \
    -c Release \
    -r "$RID" \
    --self-contained true \
    -p:Version="${VERSION}" \
    -o /app/publish

# Notices stage — combines both CycloneDX SBOMs into a curated attribution file.
# Pinned to the build platform for the same reason as the frontend stage: it runs
# node over architecture-independent JSON, so emulation buys nothing and risks SIGILL.
FROM --platform=$BUILDPLATFORM node:26-alpine@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66 AS notices
WORKDIR /work
COPY build/extract-notices.mjs ./
COPY --from=frontend /web/sbom-frontend-prod.json ./
COPY --from=build /sboms/sbom-backend.json ./
RUN node extract-notices.mjs sbom-backend.json sbom-frontend-prod.json > notices.json

# Runtime stage — minimal native deps image
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-alpine@sha256:f276c0256ffca8fe816d48ba261962b54fea1b0e6f870b6a60b3b705c89e78ac AS final
WORKDIR /app

ARG REGISTRY_URL=
# apk fetches route through the private registry's apk pull-through proxy when
# REGISTRY_URL and the registry_key secret are present (CI builds): the dl-cdn
# prefix in /etc/apk/repositories is rewritten to the private host for the
# duration of apk add, then restored, all within this one RUN so neither the
# credential nor the private host survives in the shipped layer. An empty
# REGISTRY_URL or an absent secret leaves the default dl-cdn.alpinelinux.org
# mirror in place, so the build succeeds unmodified for public/fork checkouts.
# The proxy is a cache, not a trust root, so it fails open: if the proxied apk
# add does not resolve (proxy down, apk ecosystem not yet served, index cold),
# the original repositories are restored and the packages are fetched from
# dl-cdn. This keeps the image build from hard-depending on the registry running
# ahead of it — the apk proxy is itself shipped in this image.
# hadolint ignore=DL3018,DL4006
RUN --mount=type=secret,id=registry_key \
    if [ -n "$REGISTRY_URL" ] && [ -s /run/secrets/registry_key ]; then \
      cp /etc/apk/repositories /etc/apk/repositories.orig && \
      SCHEME=$(printf '%s' "$REGISTRY_URL" | sed -E 's|^(https?)://.*|\1|') && \
      HOST=$(printf '%s' "$REGISTRY_URL" | sed -E 's|^https?://||; s|/.*||') && \
      sed -E -i "s|https://dl-cdn\.alpinelinux\.org/alpine|${SCHEME}://ci:$(cat /run/secrets/registry_key)@${HOST}/apk|" /etc/apk/repositories; \
      if ! apk add --no-cache sqlite-libs icu-libs; then \
        echo "apk proxy unreachable at ${REGISTRY_URL}; falling back to dl-cdn.alpinelinux.org" >&2; \
        cp /etc/apk/repositories.orig /etc/apk/repositories && \
        apk add --no-cache sqlite-libs icu-libs; \
      fi; \
      mv /etc/apk/repositories.orig /etc/apk/repositories; \
    else \
      apk add --no-cache sqlite-libs icu-libs; \
    fi && \
    addgroup -S dependably && adduser -S dependably -G dependably && \
    mkdir -p /data && chown dependably:dependably /data

ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false
USER dependably

ARG VERSION=0.1.0
LABEL org.opencontainers.image.source="https://github.com/dependably/dependably-community" \
      org.opencontainers.image.title="dependably" \
      org.opencontainers.image.description="Self-hosted private artifact repository for npm, PyPI, and NuGet" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build --chown=dependably:dependably /app/publish/ .
COPY --from=notices --chown=dependably:dependably /work/notices.json ./notices.json

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:8080/ready || exit 1

VOLUME ["/data"]

ENTRYPOINT ["./Dependably"]
