# syntax=docker/dockerfile:1
# Scan image for Threadscan itself. Installs PyYAML and pytest while the network is up;
# the code and its tests then run offline. Docker is not installed: the tests mock it.
FROM python:3.13-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 10101 -s /bin/bash app \
    && mkdir -p /src && chown app:app /src
RUN pip install --no-cache-dir "PyYAML>=6.0" "pytest>=8"
USER app
ENV HOME=/home/app PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
COPY --chown=app:app . /src
# Sanity: the test suite runs in the image. A failure is reported, not fatal.
RUN python -m pytest -q -p no:cacheprovider || echo "WARNING: pytest reported failures"
