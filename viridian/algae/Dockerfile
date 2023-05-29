FROM python:3.11-alpine3.17 as default

RUN apk update && apk add --virtual build-dependencies build-base gcc

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
WORKDIR /seaside/algae

RUN pip install poetry
COPY sources/*.py ./sources
COPY script.py pyproject.toml README.md ./
RUN poetry install --all-extras

ENV COMMAND true
ENV LOG_LEVEL DEBUG

ENV VPN True
ENV TUNNEL seatun
ENV CONN_MTU 1500
ENV CONN_BUFF 2000
ENV ADDRESS 127.0.0.1
ENV IN_PORT 1724
ENV OUT_PORT 1723
ENV CTRL_PORT 1725

EXPOSE $IN_PORT
ENTRYPOINT (poetry run python3 main.py -t $TUNNEL -e $VPN -m $CONN_MTU -b $CONN_BUFF -a $ADDRESS -i $IN_PORT -o $OUT_PORT &) && sh -c "$COMMAND"
