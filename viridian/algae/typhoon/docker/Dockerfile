# syntax=docker/dockerfile:1

FROM ubuntu:22.04

WORKDIR /seaside/typhoon

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Install python dependencies and build system.
RUN apt-get update && apt-get install -y --no-install-recommends python3-pip && pip install --upgrade --no-cache-dir poetry

COPY viridian/algae/pyproject.toml ./
RUN poetry install --without client,devel,script,setup,protocol

# Copy algae and test sources, also copy generated protobuf files.
COPY viridian/algae/sources/ ./sources/
COPY viridian/algae/protocol/docker/server.py ./
RUN touch __init__.py

ENV TYPHOON_CERTIFICATE=
ENV TYPHOON_ADDRESS=0.0.0.0
ENV TYPHOON_PORT=0

ENTRYPOINT ["sh", "-c", "poetry run python3 server.py -a $TYPHOON_ADDRESS -p $TYPHOON_PORT $TYPHOON_CERTIFICATE"]
