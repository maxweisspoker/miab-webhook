FROM golang:1-alpine AS builder

RUN apk update && \
    apk upgrade && \
    apk add git ca-certificates tzdata && \
    mkdir -p /workspace && \
    update-ca-certificates

WORKDIR /workspace

COPY . .

RUN go get cloud.google.com/go/compute/metadata && \
    go mod download && \
    go mod tidy

RUN env CGO_ENABLED=0 go build -o webhook -ldflags '-s -w -extldflags "-static"' . && \
    chown root:root /workspace/webhook && \
    chmod 555 /workspace/webhook

# Build from alpine instead of scratch in order to test/diagnose
#FROM alpine
FROM scratch

COPY --chown=0:0 --from=builder /workspace/webhook /webhook

# For alpine build
#RUN chmod 555 /webhook && apk update && apk --no-cache upgrade && apk add --no-cache ca-certificates tzdata && update-ca-certificates

# If you are building for alpine and want to use system ca certs and tzdata, comment out the "time/tzdata" and "github.com/breml/rootcerts" imports at the top of main.go

USER 1000

CMD ["--secure-port=8443"]
ENTRYPOINT ["/webhook"]
