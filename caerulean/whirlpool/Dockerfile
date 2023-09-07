FROM golang:1.19-alpine3.17 as builder

WORKDIR /seaside/caerulean

RUN apk add --no-cache protobuf-compiler protoc-gen-go
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

COPY vessels ./vessels

COPY caerulean/whirlpool/go.* ./
RUN go get ./...

COPY caerulean/whirlpool/sources ./
RUN go get main/m/v2

RUN protoc -I=vessels --go_out=. --experimental_allow_proto3_optional vessels/*.proto
RUN go build -o whirlpool.run


FROM alpine:3.17 as default

RUN apk add --no-cache iptables

WORKDIR /seaside/caerulean
COPY --from=builder /seaside/caerulean/whirlpool.run ./

ENV LOG_LEVEL WARNING
ENV MAX_USERS 16

ENV ADDRESS none
ENV EXTERNAL none
ENV SURFACE none
ENV SEA_PORT 8542
ENV CTRL_PORT 8543
ENV NET_PORT 8587
ENV USER_TTL 300

EXPOSE $SEA_PORT/udp
EXPOSE $CTRL_PORT/tcp
ENTRYPOINT ./whirlpool.run -a $ADDRESS -e $EXTERNAL -s $SURFACE -p $SEA_PORT -c $CTRL_PORT -t $USER_TTL -u $MAX_USERS
