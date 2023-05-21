FROM python:3.11-alpine3.17 as builder

RUN apk add --no-cache make binutils

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
WORKDIR /seaside/algae

COPY sources/*.py ./sources/
COPY Makefile ./

RUN make build EXECUTABLE_NAME=algae.run


FROM alpine:3.17 as default

WORKDIR /seaside/algae
COPY --from=builder /seaside/algae/dist/algae.run ./

ENV COMMAND true
ENV LOG_LEVEL DEBUG

ENV TUNNEL seatun
ENV CONN_MTU 1500
ENV CONN_BUFF 2000
ENV ADDRESS 127.0.0.1
ENV IN_PORT 1724
ENV OUT_PORT 1723
ENV CTRL_PORT 1725

EXPOSE $IN_PORT
ENTRYPOINT (./algae.run -t $TUNNEL -m $CONN_MTU -b $CONN_BUFF -a $ADDRESS -i $IN_PORT -o $OUT_PORT &) && sh -c "$COMMAND"
