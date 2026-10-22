# api image: static Go binary on distroless, non-root. Build from the repo root:
#   docker build -f deploy/docker/api.Dockerfile .
FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api \
 && go build -trimpath -ldflags="-s -w" -o /out/nmsctl ./cmd/nmsctl \
 && go build -trimpath -ldflags="-s -w" -o /out/poller ./cmd/poller

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/api /api
# nmsctl tools container (compose service "nmsctl", entrypoint /nmsctl)
COPY --from=build /out/nmsctl /nmsctl
# poller service (compose service "poller", entrypoint /poller)
COPY --from=build /out/poller /poller
USER 65532:65532
ENTRYPOINT ["/api"]
CMD ["serve"]
