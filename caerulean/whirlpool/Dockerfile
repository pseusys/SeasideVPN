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
ENV MAX_USERS 16

ENV ADDRESS none
ENV EXTERNAL none
ENV IN_PORT 1723
ENV OUT_PORT 1724
ENV CTRL_PORT 1725
ENV USER_TTL 300

EXPOSE $IN_PORT
EXPOSE $CTRL_PORT
ENTRYPOINT ./whirlpool.run -a $ADDRESS -e $EXTERNAL -i $IN_PORT -o $OUT_PORT -c $CTRL_PORT -t $USER_TTL -u $MAX_USERS

# TODO: open for PINGs and control ports, test: tcpdump -n -i eth0 ip
