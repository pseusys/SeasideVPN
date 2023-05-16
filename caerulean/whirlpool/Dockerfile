FROM golang:1.19-alpine3.17

RUN apk add --no-cache iptables

WORKDIR /seaside/whirlpool
COPY sources ./
COPY go.* ./

RUN go get -d -v ./...
RUN go build -o whirlpool.run

ENV ADDRESS 127.0.0.1
ENV IN_PORT 1723
ENV OUT_PORT 1724
ENV CTRL_PORT 1725

EXPOSE $IN_PORT
ENTRYPOINT ./whirlpool.run -a $ADDRESS -i $IN_PORT -o $OUT_PORT -c $CTRL_PORT
