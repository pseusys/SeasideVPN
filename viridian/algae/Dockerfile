FROM python:3.11.3-alpine3.17 as builder

RUN apk add --no-cache make binutils

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
WORKDIR /seaside/algae

COPY sources/*.py ./sources/
COPY Makefile ./

ENV EXECUTABLE algae.run
RUN make build EXECUTABLE_NAME=$EXECUTABLE


FROM alpine:3.17.3 as runner

WORKDIR /seaside/algae
COPY --from=builder /seaside/algae/dist/* ./

ENV EXECUTABLE algae.run
ENV COMMAND exit

ENV TUNNEL seatun
ENV CONN_MTU 1300
ENV CONN_BUFF 2000
ENV ADDRESS 127.0.0.1
ENV IN_PORT 1723
ENV OUT_PORT 1724

EXPOSE 1724
ENTRYPOINT (./$EXECUTABLE -t $TUNNEL -m $CONN_MTU -b $CONN_BUFF -a $ADDRESS -i $IN_PORT -o $OUT_PORT &) && sh -c "$COMMAND"
