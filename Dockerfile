# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS build

WORKDIR /src

COPY go.mod ./
COPY cmd ./cmd
COPY sfos ./sfos
COPY topology ./topology
COPY ipam ./ipam
COPY policy ./policy
COPY web ./web

RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath -ldflags="-s -w" \
      -o /out/sfos-topology ./cmd/sfos-topology

RUN CGO_ENABLED=0 go test ./...

FROM scratch

COPY --from=build /out/sfos-topology /sfos-topology

USER 65532:65532
WORKDIR /app
EXPOSE 8089

ENTRYPOINT ["/sfos-topology"]
CMD ["-config", "/app/devices.json", "-serve", "0.0.0.0:8089", "-refresh", "15m"]
