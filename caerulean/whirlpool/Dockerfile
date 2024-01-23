# syntax=docker/dockerfile:1

FROM golang:1.20-alpine3.17 as builder

WORKDIR /seaside/caerulean

RUN apk add --no-cache protobuf protobuf-dev build-base gmp-dev
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

COPY caerulean/whirlpool/go.mod ./
COPY vessels ./vessels
RUN protoc -I=vessels --go_out=. vessels/*.proto

COPY caerulean/whirlpool ./
RUN go mod tidy

RUN go build -o whirlpool.run ./sources


FROM alpine:3.17 as default

WORKDIR /seaside/caerulean

RUN apk add --no-cache iptables gmp
COPY --from=builder /seaside/caerulean/whirlpool.run ./

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

EXPOSE $SEASIDE_SEAPORT/udp
EXPOSE $SEASIDE_CTRLPORT/tcp
EXPOSE $SEASIDE_NETPORT/tcp
ENTRYPOINT ./whirlpool.run

HEALTHCHECK --interval=1m --timeout=1s --retries=3 --start-period=10s --start-interval=3s CMD netstat -tulpn | grep -q ":$SEASIDE_SEAPORT"
