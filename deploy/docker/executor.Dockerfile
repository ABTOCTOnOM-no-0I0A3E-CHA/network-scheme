# executor image: the only binary that may change devices, static on distroless, uid 65533
# (no other container runs as this user, so only it can read its keys). Build from the repo root:
#   docker build -f deploy/docker/executor.Dockerfile .
FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/executor ./cmd/executor \
 && mkdir -m 0700 /out/state

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/executor /executor
# Mount point of the executor-state volume: a new named volume takes this owner and mode.
COPY --from=build --chown=65533:65533 --chmod=0700 /out/state /var/lib/executor
USER 65533:65533
ENTRYPOINT ["/executor"]
CMD ["run"]
