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

ENV LOG_LEVEL WARNING
ENV MAX_USERS 16

ENV OWNER_KEY none
ENV PUBLIC_KEY none
ENV ADDRESS none
ENV EXTERNAL none
ENV SEA_PORT 8542
ENV CTRL_PORT 8543
ENV NET_PORT 8587
ENV MAX_USERS 10
ENV MAX_ADMINS 5

EXPOSE $SEA_PORT/udp
EXPOSE $CTRL_PORT/tcp
EXPOSE $NET_PORT/tcp
ENTRYPOINT ./whirlpool.run -a $ADDRESS -e $EXTERNAL -p $SEA_PORT -c $CTRL_PORT -n $NET_PORT

# TODO: after docker engine 25 is out, change to: --interval=1m --timeout=1s --retries=3 --start-period=10s --start-interval=3s
HEALTHCHECK --interval=3s --timeout=1s --retries=3 --start-period=10s CMD netstat -tulpn | grep -q ":$SEA_PORT"
