FROM golang:1.19-alpine3.17

RUN apk add --no-cache iptables

WORKDIR /go/src/app
COPY sources ./
COPY go.* ./

RUN go get -d -v ./...
RUN go build -o app.run

ENTRYPOINT ["/bin/sh", "-c"]
