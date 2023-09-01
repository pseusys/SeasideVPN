FROM golang:1.19-alpine3.17 as builder

WORKDIR /seaside/caerulean

COPY go.* ./
RUN go get ./...

COPY sources ./
RUN go get main/m/v2

RUN go build -o whirlpool.run


FROM alpine:3.17 as default

RUN apk add --no-cache iptables

WORKDIR /seaside/caerulean
COPY --from=builder /seaside/caerulean/whirlpool.run ./

ENV LOG_LEVEL WARNING
ENV MAX_USERS 16

ENV ADDRESS none
ENV EXTERNAL none
ENV SEA_PORT 8542
ENV CTRL_PORT 8543
ENV USER_TTL 300

EXPOSE $SEA_PORT/udp
EXPOSE $CTRL_PORT/tcp
ENTRYPOINT ./whirlpool.run -a $ADDRESS -e $EXTERNAL -p $SEA_PORT -c $CTRL_PORT -t $USER_TTL -u $MAX_USERS
