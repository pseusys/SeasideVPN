FROM golang:1.19-alpine3.17 as builder

WORKDIR /seaside/caerulean

RUN apk add --no-cache protobuf protobuf-dev
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

COPY caerulean/whirlpool/go.* ./
RUN go get ./...

COPY vessels ./vessels
RUN protoc -I=vessels --go_out=. --experimental_allow_proto3_optional vessels/*.proto

COPY caerulean/whirlpool/main ./
RUN go get main/m/v2

RUN go build -o whirlpool.run


FROM alpine:3.17 as default

WORKDIR /seaside/caerulean

RUN apk add --no-cache iptables
COPY --from=builder /seaside/caerulean/whirlpool.run ./

ENV LOG_LEVEL WARNING
ENV MAX_USERS 16

ENV OWNER_KEY none
ENV ADDRESS none
ENV EXTERNAL none
ENV SURFACE none
ENV SEA_PORT 8542
ENV CTRL_PORT 8543
ENV NET_PORT 8587
ENV USER_TTL 300
ENV RSA_LENGTH 512

EXPOSE $SEA_PORT/udp
EXPOSE $CTRL_PORT/tcp
EXPOSE $NET_PORT/tcp
ENTRYPOINT ./whirlpool.run -a $ADDRESS -e $EXTERNAL -s $SURFACE -p $SEA_PORT -c $CTRL_PORT -n $NET_PORT -t $USER_TTL -u $MAX_USERS -o $OWNER_KEY

# TODO: after docker engine 25 is out, change to: --interval=1m --timeout=1s --retries=3 --start-period=10s --start-interval=3s
HEALTHCHECK --interval=3s --timeout=1s --retries=3 --start-period=10s CMD wget -qO- http://$ADDRESS:$NET_PORT/public | wc -c | xargs test $RSA_LENGTH -lt
