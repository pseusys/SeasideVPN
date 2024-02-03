# syntax=docker/dockerfile:1

# Docker image for building whirlpool executable and testing
FROM golang:1.20-alpine3.17 as builder

WORKDIR /seaside/caerulean

# GMP and protobuf development libraries are required for executable building.
# Go lint and iptables are required for testing.
RUN apk add --no-cache iptables protobuf protobuf-dev build-base gmp-dev
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install golang.org/x/lint/golint@latest

# Copy whirlpool go.mod, protobuf files and generate protobuf sources.
COPY caerulean/whirlpool/go.mod ./
COPY vessels ./vessels
RUN protoc -I=vessels --go_out=. vessels/*.proto

# Copy whirlpool code and install required libraries.
COPY caerulean/whirlpool ./
RUN go mod tidy

# Build executable.
RUN go build -o whirlpool.run ./sources


# Docker image for whirlpool executable production running
FROM alpine:3.17 as default

WORKDIR /seaside/caerulean

# Install iptables and gmp packages for whirlpool running.
RUN apk add --no-cache iptables gmp
COPY --from=builder /seaside/caerulean/whirlpool.run ./

# Setup environmental variables.
ENV SEASIDE_SEAPORT 8542
ENV SEASIDE_CTRLPORT 8543
ENV SEASIDE_NETPORT 8587

ENV SEASIDE_AUTH auth

ENV SEASIDE_MAX_USERS 10
ENV SEASIDE_MAX_ADMINS 5

ENV SEASIDE_TUNNEL_MTU 1500
ENV SEASIDE_VPN_DATA_LIMIT -1
ENV SEASIDE_CONTROL_PACKET_LIMIT 2
ENV SEASIDE_HTTP_PACKET_LIMIT 3
ENV SEASIDE_ICMP_PACKET_LIMIT 5
ENV SEASIDE_BURST_LIMIT_MULTIPLIER 3

ENV SEASIDE_LOG_LEVEL WARNING

# Expose ports and set entrypoint.
EXPOSE $SEASIDE_SEAPORT/udp
EXPOSE $SEASIDE_CTRLPORT/tcp
EXPOSE $SEASIDE_NETPORT/tcp
ENTRYPOINT ./whirlpool.run

# Establish healthcheck: netstat on seaside port.
HEALTHCHECK --interval=1m --timeout=1s --retries=3 --start-period=10s --start-interval=3s CMD netstat -tulpn | grep -q ":$SEASIDE_SEAPORT"
