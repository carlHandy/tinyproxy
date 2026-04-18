FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o go-tinyproxy ./cmd/tinyproxy/

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /src/go-tinyproxy /usr/local/bin/go-tinyproxy
COPY docker/vhosts.default.conf /etc/go-tinyproxy/vhosts.conf
COPY config/fingerprints.conf /etc/go-tinyproxy/fingerprints.conf
COPY static/ /usr/share/go-tinyproxy/static/
EXPOSE 80 443
ENTRYPOINT ["go-tinyproxy"]
