FROM golang:1.19-alpine3.17

# TODO: remove tcpdump
RUN apk add --no-cache iptables tcpdump

WORKDIR /seaside/whirlpool
COPY sources ./
COPY go.* ./

RUN go get -d -v ./...
RUN go build -o whirlpool.run

ENTRYPOINT ["/bin/sh", "-c"]
