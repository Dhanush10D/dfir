# syntax=docker/dockerfile:1.7
# dfirbench worker image (Celery), also the parser sandbox image (same image, other command:
# `python -m app.sandbox.server` in the `parser-sandbox` service, Phase 10). Build context:
# backend/; extra context "infra": infra/docker/ (pinned Volatility 3 requirements).
#
# Stage layout (guide 5.2, 21.2; Phase 6 spec decisions 6-8):
#   tools   - Linux forensic engines, pinned, versions recorded in /opt/dfir/tool-versions.txt
#             (read by the parsers for run manifests):
#               * Sleuth Kit (mmls, fls) from Debian bookworm apt; E01 via Debian's libewf build;
#               * Volatility 3 in its own venv (/opt/dfir/vol3, `vol` on PATH), installed from
#                 infra/docker/volatility-requirements.txt with --require-hashes (every
#                 dependency pinned by version and hash). dfirbench never imports it
#                 (Volatility Software License); symbol packs are not baked in
#                 (VOLATILITY_SYMBOLS_DIR mounts them), and the wrapper always runs --offline;
#               * Zeek is NOT installed (optional engine: hundreds of MB from a third-party repo).
#                 The `zeek` parser fails the job with a clear "not installed" error; add it in a
#                 derived image or via TOOL_SEARCH_PATH if needed.
#             YARA (yara-python wheel with libyara), pefile, dpkt and LnkParse3 are Python deps.
#   build   - Python venv with the dfirbench package.
#   runtime - tools + venv, non-root.
# Python wrappers detect a missing binary and fail the job with a clear error.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

FROM ${PYTHON_IMAGE} AS tools
ARG SLEUTHKIT_VERSION=4.11.1+dfsg-1+b1
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
COPY --from=infra volatility-requirements.txt /tmp/volatility-requirements.txt
RUN apt-get update \
 && apt-get install -y --no-install-recommends "sleuthkit=${SLEUTHKIT_VERSION}" \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /opt/dfir/bin \
 && python -m venv /opt/dfir/vol3 \
 && /opt/dfir/vol3/bin/pip install --require-hashes --no-deps -r /tmp/volatility-requirements.txt \
 && rm /tmp/volatility-requirements.txt \
 && ln -s /opt/dfir/vol3/bin/vol /opt/dfir/bin/vol \
 && { echo "dfirbench worker toolchain"; \
      echo "sleuthkit $(dpkg-query -W -f='${Version}' sleuthkit)"; \
      echo "volatility3 $(/opt/dfir/vol3/bin/pip show volatility3 | sed -n 's/^Version: //p')"; \
      echo "zeek not-installed"; } > /opt/dfir/tool-versions.txt \
 && cat /opt/dfir/tool-versions.txt

FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
COPY pyproject.toml ./
RUN mkdir app && touch app/__init__.py && pip install . && rm -rf app build
COPY app ./app
RUN pip install --no-deps --force-reinstall .

FROM tools AS runtime
ENV PATH=/opt/venv/bin:/opt/dfir/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DFIR_TOOL_VERSIONS=/opt/dfir/tool-versions.txt
RUN groupadd --system --gid 10001 dfir \
 && useradd --system --uid 10001 --gid dfir --home-dir /work --shell /usr/sbin/nologin dfir \
 && mkdir -p /work && chown dfir:dfir /work \
 && useradd --system --uid 10002 --gid dfir --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin dfirparse \
 && install -d -o dfir -g dfir -m 0700 /var/lib/dfirbench/keys /var/lib/dfirbench/scratch \
      /var/lib/dfirbench/spool/out \
 && install -d -o dfir -g dfir -m 0750 /var/lib/dfirbench/spool/in \
 && install -d -o dfir -g dfir -m 0710 /var/lib/dfirbench/sandbox-work
COPY --from=build /opt/venv /opt/venv
WORKDIR /work
USER dfir:dfir
HEALTHCHECK --interval=20s --timeout=15s --retries=6 --start-period=20s \
  CMD ["sh", "-c", "celery -A app.workers.celery_app inspect ping -d worker@$HOSTNAME --timeout 5 | grep -q pong"]
CMD ["celery", "-A", "app.workers.celery_app", "worker", "-Q", "default,parse,detect,ai,reports", "-c", "2", "-n", "worker@%h", "--loglevel", "INFO"]
