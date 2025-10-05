# syntax=docker/dockerfile:1

# Docker image for building whirlpool executable and testing
FROM golang:1.24-alpine3.22 AS builder

WORKDIR /seaside/caerulean

ARG RUNNING_IN_CI

# Protogo library is required for executable building.
# Nftables are required for testing.
RUN apk add --no-cache nftables && go install github.com/pseusys/protogo@latest

ENV RUNNING_IN_CI=${RUNNING_IN_CI:-0}

# Copy whirlpool go.mod, protobuf files and generate protobuf sources.
COPY caerulean/whirlpool/go.mod ./
RUN go mod download

COPY vessels ./vessels
ENV PROTOGO_PROTOC_INCLUDE=standard
RUN protogo -- protoc -I=vessels --go_out=. --go-grpc_out=. vessels/*.proto

COPY caerulean/whirlpool ./
RUN go mod tidy

RUN go build -o whirlpool.run ./sources


# Docker image for whirlpool executable production running
FROM alpine:3.22 AS default

WORKDIR /seaside/caerulean

# Install nftables package for whirlpool running.
RUN apk add --no-cache nftables
COPY --from=builder /seaside/caerulean/whirlpool.run ./

# Setup environmental variables.
ENV SEASIDE_API_PORT=8587

ENV SEASIDE_CERTIFICATE_PATH=certificates
ENV SEASIDE_LOG_PATH=logs

ENV SEASIDE_MAX_VIRIDIANS=10
ENV SEASIDE_MAX_ADMINS=5

ENV SEASIDE_TUNNEL_MTU=1500
ENV SEASIDE_TUNNEL_NAME=seatun
ENV SEASIDE_VPN_DATA_LIMIT=-1
ENV SEASIDE_CONTROL_PACKET_LIMIT=2
ENV SEASIDE_ICMP_PACKET_LIMIT=5
ENV SEASIDE_BURST_LIMIT_MULTIPLIER=3

ENV SEASIDE_LOG_LEVEL=WARNING

# Certificates volume.
VOLUME /seaside/caerulean/certificates

# Expose ports and set entrypoint.
EXPOSE $SEASIDE_API_PORT/tcp
ENTRYPOINT ["./whirlpool.run"]

# Establish healthcheck: netstat on seaside port.
HEALTHCHECK --interval=1m --timeout=1s --retries=3 --start-period=10s --start-interval=3s CMD netstat -tulpn | grep -q ":$SEASIDE_API_PORT"


FROM default AS default-certified

ARG SEASIDE_ADDRESS
ENV SEASIDE_ADDRESS=$SEASIDE_ADDRESS

ENV SEASIDE_CERTIFICATE_PATH=/seaside/caerulean/certificates/caerulean

COPY viridian/algae /tmp/seaside-algae

RUN apk add --no-cache python3 py3-pip && cd /tmp/seaside-algae && \
    pip3 install --no-cache-dir --break-system-packages .[setup] && \
    python3 -m setup --just-certs ${SEASIDE_ADDRESS} && \
    apk --purge del python3 py3-pip

ENTRYPOINT ["sh", "-c", "cp -r /tmp/seaside-algae/certificates ./ && ./whirlpool.run"]

FROM default-certified AS default-routed

ARG NETWORK_GATEWAY
ENV ARG_NETWORK_GATEWAY=$NETWORK_GATEWAY

# Setup default route IP and run viridian algae with command.
ENTRYPOINT ["sh", "-c", "ip route replace default via $ARG_NETWORK_GATEWAY && cp -r /tmp/seaside-algae/certificates ./ && ./whirlpool.run"]
