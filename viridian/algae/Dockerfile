FROM python:3.11-alpine3.17 as default

RUN apk update && apk add --virtual build-dependencies build-base gcc

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
WORKDIR /seaside/algae

RUN pip install --no-cache-dir poetry

COPY sources/*.py ./sources/
COPY test/*.py ./test/
COPY script.py pyproject.toml README.md ./

RUN poetry install --all-extras

ENV COMMAND true
ENV LOG_LEVEL DEBUG

ENV VPN True
ENV TUNNEL seatun
ENV CONN_MTU 1500
ENV CONN_BUFF 2000
ENV ADDRESS 127.0.0.1
ENV SEA_PORT 8542
ENV CTRL_PORT 8543

EXPOSE $SEA_PORT/udp
EXPOSE $CTRL_PORT/tcp
ENTRYPOINT poetry run execute -t $TUNNEL -e $VPN -m $CONN_MTU -b $CONN_BUFF -a $ADDRESS -p $SEA_PORT
