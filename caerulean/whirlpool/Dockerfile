# syntax=docker/dockerfile:1

# Docker image for building whirlpool executable and testing
FROM golang:1.24-alpine3.22 AS builder

WORKDIR /seaside/caerulean

ARG RUNNING_IN_CI

# Flatc compiler is required for executable building.
# Go lint and nftables are required for testing.
RUN apk add --no-cache nftables && go install github.com/pseusys/protogo@latest

ENV RUNNING_IN_CI=${RUNNING_IN_CI:-0}

# Copy whirlpool go.mod, flatbuffers files and generate flatbuffers sources.
COPY caerulean/whirlpool/go.mod ./
RUN go mod download

COPY vessels ./vessels
RUN protogo -- flatc -g --grpc --reflect-types -I vessels vessels/*.fbs

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

RUN apk add --no-cache openssl
RUN mkdir -p /tmp/certificates/caerulean && mkdir -p /tmp/certificates/viridian && cd /tmp/certificates \
    && openssl req -newkey rsa:2048 -nodes -keyout viridian/cert.key -out viridian/cert.csr -subj "/C=TS/ST=TestState/L=PC/O=SeasideVPN/OU=seaside/CN=SeasideVPNViridian" -addext "subjectAltName = IP:${SEASIDE_ADDRESS}" -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=clientAuth" \
    && openssl req -newkey rsa:2048 -nodes -keyout caerulean/cert.key -out caerulean/cert.csr -subj "/C=TS/ST=TestState/L=PC/O=SeasideVPN/OU=seaside/CN=SeasideVPNCaerulean" -addext "subjectAltName = IP:${SEASIDE_ADDRESS}" -addext "keyUsage=critical,digitalSignature,keyEncipherment" -addext "extendedKeyUsage=serverAuth" \
    && openssl req -newkey rsa:2048 -nodes -new -x509  -keyout caerulean/rootCA.key -out caerulean/rootCA.crt -days 365250 -subj "/C=TS/ST=TestState/L=PC/O=SeasideVPN/OU=seaside/CN=SeasideVPNRootCA" -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    && openssl x509 -req -CA caerulean/rootCA.crt -CAkey caerulean/rootCA.key -in caerulean/cert.csr -out caerulean/cert.crt -days 365250 -copy_extensions=copyall \
    && openssl x509 -req -CA caerulean/rootCA.crt -CAkey caerulean/rootCA.key -in viridian/cert.csr -out viridian/cert.crt -days 365250 -copy_extensions=copyall \
    && chmod 644 */*.key && cp caerulean/rootCA.* viridian/

ENTRYPOINT ["sh", "-c", "cp -r /tmp/certificates ./ && ./whirlpool.run"]


FROM default-certified AS default-routed

ARG NETWORK_GATEWAY
ENV ARG_NETWORK_GATEWAY=$NETWORK_GATEWAY

# Setup default route IP and run viridian algae with command.
ENTRYPOINT ["sh", "-c", "ip route replace default via $ARG_NETWORK_GATEWAY && cp -r /tmp/certificates ./ && ./whirlpool.run"]
