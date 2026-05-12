# Frontend build stage
FROM node:22-alpine AS frontend
WORKDIR /web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run sbom
RUN npm run build

# Backend build stage — restore, generate backend SBOM, publish
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src

COPY Dependably.sln .
COPY Directory.Build.props .
COPY src/Dependably/Dependably.csproj src/Dependably/
ARG TARGETARCH
ARG VERSION=0.1.0
RUN case "$TARGETARCH" in \
      amd64) echo linux-musl-x64 ;; \
      *) echo linux-musl-arm64 ;; \
    esac > /tmp/rid && \
    dotnet restore src/Dependably/Dependably.csproj -r $(cat /tmp/rid)
RUN dotnet tool install CycloneDX --tool-path /tools \
 && /tools/dotnet-CycloneDX src/Dependably/Dependably.csproj \
        -o /sboms -fn sbom-backend.json -F json -spv 1.6 \
        --exclude-dev

COPY src/Dependably/ src/Dependably/
COPY --from=frontend /src/Dependably/wwwroot/ src/Dependably/wwwroot/
RUN dotnet publish src/Dependably/Dependably.csproj \
    -c Release \
    -r $(cat /tmp/rid) \
    --self-contained true \
    -p:Version=${VERSION} \
    -o /app/publish

# Notices stage — combines both CycloneDX SBOMs into a curated attribution file
FROM node:22-alpine AS notices
WORKDIR /work
COPY build/extract-notices.mjs ./
COPY --from=frontend /web/sbom-frontend.json ./
COPY --from=build /sboms/sbom-backend.json ./
RUN node extract-notices.mjs sbom-backend.json sbom-frontend.json > notices.json

# Runtime stage — minimal native deps image
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-alpine AS final
WORKDIR /app

RUN apk add --no-cache sqlite-libs icu-libs && \
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

ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:8080/ready || exit 1

VOLUME ["/data"]

ENTRYPOINT ["./Dependably"]
