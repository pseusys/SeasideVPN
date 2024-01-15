FROM golang:1.20-alpine3.17 as builder

WORKDIR /seaside/caerulean

RUN apk add --no-cache protobuf>=24.4 protobuf-dev>=24.4
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

COPY caerulean/whirlpool/go.mod ./
RUN go get ./...

COPY vessels ./vessels
RUN protoc -I=vessels --go_out=. vessels/*.proto

COPY caerulean/whirlpool ./
RUN go mod tidy

RUN go build -o whirlpool.run ./sources


FROM alpine:3.17 as default

WORKDIR /seaside/caerulean

RUN apk add --no-cache iptables
COPY --from=builder /seaside/caerulean/whirlpool.run ./

ENV SEASIDE_SEAPORT 8542
ENV SEASIDE_CTRLPORT 8543
ENV SEASIDE_NETPORT 8587

ENV SEASIDE_AUTH auth

ENV SEASIDE_MAX_USERS 10
ENV SEASIDE_MAX_ADMINS 5

ENV SEASIDE_TUNNEL_MTU 1500
ENV SEASIDE_LOG_LEVEL WARNING

EXPOSE $SEASIDE_SEAPORT/udp
EXPOSE $SEASIDE_CTRLPORT/tcp
EXPOSE $SEASIDE_NETPORT/tcp
ENTRYPOINT ./whirlpool.run

# TODO: after docker engine 25 is out, change to: --interval=1m --timeout=1s --retries=3 --start-period=10s --start-interval=3s
HEALTHCHECK --interval=3s --timeout=1s --retries=3 --start-period=10s CMD netstat -tulpn | grep -q ":$SEASIDE_SEAPORT"
