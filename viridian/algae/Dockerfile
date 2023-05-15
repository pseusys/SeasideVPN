FROM python:3.11.3-alpine3.17

# TODO: remove tcpdump
RUN apk add --no-cache tcpdump

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
WORKDIR /seaside/algae

COPY sources/*.py ./

ENTRYPOINT ["/bin/sh", "-c"]
