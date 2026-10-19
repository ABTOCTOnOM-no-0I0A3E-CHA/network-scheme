# gateway image: Caddy serving the panel bundle, non-root. Build from the repo root:
#   docker build -f deploy/docker/gateway.Dockerfile .
FROM oven/bun:1.4.3-alpine@sha256:629e17411f1f129dbec3af78d5af9c9f2a937435c80349437206c6b0b7422373 AS web
WORKDIR /src/web/app
COPY web/app/package.json web/app/bun.lock ./
RUN bun install --frozen-lockfile
COPY web/app/ ./
RUN bun run build

FROM caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f
# The binary carries cap_net_bind_service; with cap_drop: [ALL] the kernel refuses
# to exec it. The gateway listens on 8443 and needs no capability, so drop it.
# /data and /config are chowned so the named volume is initialized writable.
RUN setcap -r /usr/bin/caddy && chown 65532:65532 /data /config
COPY --from=web /src/web/app/dist /srv/app
USER 65532:65532
