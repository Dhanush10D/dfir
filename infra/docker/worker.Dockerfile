# syntax=docker/dockerfile:1.7
# dfirbench worker image (Celery). Build context: backend/
#
# Stage layout (guide 5.2, 21.2):
#   tools   - Linux forensic engines, pinned. EMPTY in Phase 0; Phase 6 adds Plaso, Sleuth Kit,
#             Volatility 3, Hayabusa, Zeek, tshark, YARA, libewf here and records versions in
#             /opt/dfir/tool-versions.txt for run manifests.
#   build   - Python venv with the dfirbench package.
#   runtime - tools + venv, non-root.
# Python wrappers must detect a missing binary and fail the job with a clear error.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm

FROM ${PYTHON_IMAGE} AS tools
# Phase 6: pinned apt packages / release downloads go here, e.g.
#   ARG SLEUTHKIT_VERSION=...
#   RUN apt-get update && apt-get install -y --no-install-recommends sleuthkit=${SLEUTHKIT_VERSION} ...
RUN mkdir -p /opt/dfir/bin \
 && printf 'dfirbench worker toolchain\nphase0: no forensic binaries installed\n' > /opt/dfir/tool-versions.txt

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
 && install -d -o dfir -g dfir -m 0700 /var/lib/dfirbench/keys /var/lib/dfirbench/scratch
COPY --from=build /opt/venv /opt/venv
WORKDIR /work
USER dfir:dfir
HEALTHCHECK --interval=20s --timeout=15s --retries=6 --start-period=20s \
  CMD ["sh", "-c", "celery -A app.workers.celery_app inspect ping -d worker@$HOSTNAME --timeout 5 | grep -q pong"]
CMD ["celery", "-A", "app.workers.celery_app", "worker", "-Q", "default,parse,detect,ai,reports", "-c", "2", "-n", "worker@%h", "--loglevel", "INFO"]
