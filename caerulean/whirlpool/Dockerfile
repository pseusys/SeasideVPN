# syntax=docker/dockerfile:1

# Docker image for building whirlpool executable and testing
FROM golang:1.20-alpine3.17 as builder

WORKDIR /seaside/caerulean

# Protobuf development library are required for executable building.
# Go lint and iptables are required for testing.
RUN apk add --no-cache iptables protobuf protobuf-dev openssl \
    && go install google.golang.org/protobuf/cmd/protoc-gen-go@latest \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest \
    && go install golang.org/x/lint/golint@latest

# Generate TSL certificates for the server
# TODO: use volumes instead
RUN mkdir secure/ \
    && openssl ecparam -genkey -name prime256v1 -noout -out secure/cert.key \
    && openssl req -new -x509 -sha256 -key secure/cert.key -out secure/cert.crt -days 365250 -subj "/C=FR/ST=France/L=Paris/O=seasidevpn/OU=seasidevpn-whirlpool/CN=pseusys"

# Copy whirlpool go.mod, protobuf files and generate protobuf sources.
COPY caerulean/whirlpool/go.mod ./
COPY vessels ./vessels
RUN protoc -I=vessels --go_out=. --go-grpc_out=. vessels/*.proto

# Copy whirlpool code and install required libraries.
COPY caerulean/whirlpool ./
RUN go mod tidy

# Build executable.
RUN go build -o whirlpool.run ./sources


# Docker image for whirlpool executable production running
FROM alpine:3.17 as default

WORKDIR /seaside/caerulean

# Install iptables package for whirlpool running.
RUN apk add --no-cache iptables
COPY --from=builder /seaside/caerulean/secure ./secure/
COPY --from=builder /seaside/caerulean/whirlpool.run ./

# Setup environmental variables.
ENV SEASIDE_CTRLPORT 8587

ENV SEASIDE_AUTH auth

ENV SEASIDE_MAX_VIRIDIANS 10
ENV SEASIDE_MAX_ADMINS 5

ENV SEASIDE_VIRIDIAN_WAITING_OVERTIME 5
ENV SEASIDE_VIRIDIAN_FIRST_HEALTHCHECK_DELAY 3

ENV SEASIDE_TUNNEL_MTU 1500
ENV SEASIDE_VPN_DATA_LIMIT -1
ENV SEASIDE_CONTROL_PACKET_LIMIT 2
ENV SEASIDE_HTTP_PACKET_LIMIT 3
ENV SEASIDE_ICMP_PACKET_LIMIT 5
ENV SEASIDE_BURST_LIMIT_MULTIPLIER 3

ENV SEASIDE_LOG_LEVEL WARNING

# Expose ports and set entrypoint.
EXPOSE $SEASIDE_CTRLPORT/tcp
ENTRYPOINT ./whirlpool.run

# Establish healthcheck: netstat on seaside port.
HEALTHCHECK --interval=1m --timeout=1s --retries=3 --start-period=10s --start-interval=3s CMD netstat -tulpn | grep -q ":$SEASIDE_CTRLPORT"
