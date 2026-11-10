# syntax=docker/dockerfile:1
#
# Scan overlay: adds the agent runtime on top of the TARGET's own image, so the agent
# sees exactly the environment the target was built in. Built by `vulnscan scan` with
# network on (like the target build); everything after this runs offline.
#
#   BASE_IMAGE   the image built from targets/<name>/Dockerfile
#   TARGET_USER  the user that image ends with (read by the host from the image config)
#   AGENT_SDK_SPEC  pip requirement for the Claude Agent SDK; pin it for reproducible scans,
#                   e.g. claude-agent-sdk==X.Y.Z (the wheel ships the Claude Code CLI)
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG TARGET_USER=root
ARG AGENT_SDK_SPEC=claude-agent-sdk

USER root
RUN set -eux; \
    if command -v apt-get >/dev/null 2>&1; then \
        apt-get update; \
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            python3 python3-venv git patch bash ca-certificates curl; \
        rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
        apk add --no-cache python3 py3-pip git patch bash ca-certificates curl; \
    elif command -v dnf >/dev/null 2>&1; then \
        dnf install -y python3 git patch bash ca-certificates curl; dnf clean all; \
    else \
        echo "unsupported base image: the overlay needs apt, apk or dnf" >&2; exit 1; \
    fi; \
    python3 -c 'import sys; assert sys.version_info >= (3, 10), "the Agent SDK needs Python 3.10+"'

RUN python3 -m venv /opt/vulnscan/venv \
    && /opt/vulnscan/venv/bin/pip install --no-cache-dir "${AGENT_SDK_SPEC}" \
    && /opt/vulnscan/venv/bin/python -c "import claude_agent_sdk; print('claude-agent-sdk', getattr(claude_agent_sdk, '__version__', '?'))"

COPY agent_runner.py verify_driver.sh /opt/vulnscan/
RUN chmod 0755 /opt/vulnscan /opt/vulnscan/verify_driver.sh && chmod 0644 /opt/vulnscan/agent_runner.py

USER ${TARGET_USER}
