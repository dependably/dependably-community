# Deliberately carries no `# syntax=` directive: BuildKit fetches an external
# frontend from docker.io to honour one, and nothing here needs it — no
# RUN --mount, no heredocs, and an ARG ahead of FROM is built-in behaviour.
# The built-in frontend keeps this build free of any Docker Hub pull.
# Prebaked CI tool image for the two jobs that need small OS-level utilities on
# top of the .NET SDK: sca-backend (jq, for parsing `dotnet list package
# --vulnerable` output) and sonarqube-check (a JRE for the SonarScanner engine,
# plus a Node runtime for the JS analysis sensors). Baking these in removes the
# per-run `apt-get install` from both job scripts.
ARG DEP_IMAGE_REGISTRY=dependably.northwardlabs.ca
FROM ${DEP_IMAGE_REGISTRY}/dotnet/sdk:10.0@sha256:548d93f8a18a1acbe6cc127bc4f47281430d34a9e35c18afa80a8d6741c2adc3

# hadolint ignore=DL3008
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
       jq \
       openjdk-17-jre-headless \
       nodejs \
    && rm -rf /var/lib/apt/lists/*
