FROM golang:1.19-alpine3.17 as builder

WORKDIR /seaside/algae

COPY go.* ./
RUN go get ./...

COPY sources ./
RUN go get main/m/v2

RUN go build -o whirlpool.run


FROM alpine:3.17 as default

RUN apk add --no-cache iptables

WORKDIR /seaside/algae
COPY --from=builder /seaside/algae/whirlpool.run ./

ENV LOG_LEVEL WARNING

ENV ADDRESS 127.0.0.1
ENV EXTERNAL 127.0.0.1
ENV IN_PORT 1723
ENV OUT_PORT 1724
ENV CTRL_PORT 1725

EXPOSE $IN_PORT
ENTRYPOINT ./whirlpool.run -a $ADDRESS -e $EXTERNAL -i $IN_PORT -o $OUT_PORT -c $CTRL_PORT
