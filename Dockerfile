# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# SPDX-License-Identifier: AGPL-3.0-only
#
# Vocdoni OAuth: upstream Dex with the Vocdoni configuration and logo.
#
#   docker build -t vocdoni-oauth .              # production image (default target)
#   docker build --target dev -t vocdoni-oauth:dev-config .   # + local password DB config
#
# The upstream entrypoint renders /etc/dex/config.yaml with gomplate (PORT,
# ISSUER and secret presence checks only; secret values never go through the
# template) and execs `dex serve`. The base image is pinned by digest
# (Dependabot updates it); the upstream image runs as dex (uid 1001).

FROM ghcr.io/dexidp/dex:v2.46.0@sha256:933fcd3f523338c847b88ef84a7145fb2fcb7b9917f08418612afeaaa2001777 AS service
ARG VERSION=devel
LABEL org.opencontainers.image.title="vocdoni-oauth" \
      org.opencontainers.image.description="Central OpenID Connect provider for Vocdoni internal tools (Dex with Google)" \
      org.opencontainers.image.source="https://github.com/vocdoni/oauth" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}"
COPY --chown=root:root --chmod=0444 config.yaml /etc/dex/config.yaml
COPY --chown=root:root --chmod=0444 theme/logo.png /srv/dex/web/themes/light/vocdoni-logo.png
# /data is the SQLite volume. Owned by dex so a local named volume works as
# uid 1001; Railway mounts its volume root-owned and runs with RAILWAY_RUN_UID=0.
USER root
RUN mkdir -p /data && chown dex:dex /data
USER dex:dex
ENV PORT=5556
VOLUME /data
EXPOSE 5556
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${PORT}/healthz" || exit 1
CMD ["dex", "serve", "/etc/dex/config.yaml"]

# ---- dev: the same image plus the local password-DB configuration ----------
FROM service AS dev
COPY --chown=root:root --chmod=0444 dev/config.yaml /etc/dex/dev.yaml
CMD ["dex", "serve", "/etc/dex/dev.yaml"]

# ---- default target: the production image -----------------------------------
FROM service
