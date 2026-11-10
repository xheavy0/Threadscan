# syntax=docker/dockerfile:1
# Scan image for the demo target (examples/vulnapp). Standard library only, so the
# build fetches nothing but curl; the app and its tests run offline afterwards.
FROM python:3.13-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10101 -s /bin/bash app \
    && mkdir -p /src && chown app:app /src
USER app
ENV HOME=/home/app
WORKDIR /src
COPY --chown=app:app . /src
# Sanity: the app's own tests pass in the image.
RUN python -m unittest discover -s tests
