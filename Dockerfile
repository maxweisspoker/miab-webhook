FROM golang:1.17-alpine AS builder

RUN apk update && apk upgrade && apk add git && mkdir -p /workspace

WORKDIR /workspace

COPY . .

RUN go mod download

RUN env CGO_ENABLED=0 go build -o webhook -ldflags '-s -w -extldflags "-static"' .

FROM alpine

COPY --from=builder /workspace/webhook /usr/local/bin/webhook

RUN chmod 755 /usr/local/bin/webhook && apk update && apk --no-cache upgrade && apk add --no-cache ca-certificates

USER 1000

ENTRYPOINT ["/usr/local/bin/webhook"]
