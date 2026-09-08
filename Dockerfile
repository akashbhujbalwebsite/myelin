# Build stage
FROM docker.io/golang:1.23 AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/      cmd/
COPY api/      api/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -a \
    -ldflags="-X github.com/akashbhujbalwebsite/myelin/internal/cli.Version=${VERSION}" \
    -o myelin-operator ./cmd/operator

# Final image — distroless for minimal attack surface (CNCF standard)
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/myelin-operator .
USER 65532:65532

ENTRYPOINT ["/myelin-operator"]
