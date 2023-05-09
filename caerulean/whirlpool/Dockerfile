FROM golang:1.19-alpine3.17

RUN apk add --no-cache iptables tcpdump

WORKDIR /go/whirlpool
COPY sources ./
COPY go.* ./

RUN go get -d -v ./...
RUN go build -o whirlpool.run

ENTRYPOINT ["/bin/sh", "-c"]
