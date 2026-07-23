FROM python:3.13-slim

ARG VERSION=dev
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="LumenTrace" \
      org.opencontainers.image.description="Automated power recovery for your network" \
      org.opencontainers.image.url="https://github.com/patricksmith0330/lumentrace" \
      org.opencontainers.image.source="https://github.com/patricksmith0330/lumentrace" \
      org.opencontainers.image.documentation="https://github.com/patricksmith0330/lumentrace#readme" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="Unlicense"

RUN apt-get update \
 && apt-get install -y --no-install-recommends gosu libcap2-bin nut-client iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN groupadd --gid 10001 lumentrace \
 && useradd --uid 10001 --gid lumentrace --no-create-home --shell /usr/sbin/nologin lumentrace

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
 && python -m pip install --no-cache-dir -r requirements.txt \
 && setcap cap_net_raw=ep "$(readlink -f "$(command -v python)")"

COPY manage.py config.py models.py docker-entrypoint.sh ./
COPY lumentrace/ ./lumentrace/
COPY core/ ./core/
COPY utils/ ./utils/
COPY services/ ./services/
COPY templates/ ./templates/
COPY static/ ./static/

RUN mkdir -p /tmp/lumentrace-build \
 && SECRET_KEY=container-build-key-not-used-at-runtime-0001 DATA_DIR=/tmp/lumentrace-build \
      python manage.py collectstatic --noinput \
 && mkdir -p /data \
 && chown -R lumentrace:lumentrace /data /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=3)" || exit 1
ENTRYPOINT ["/bin/sh", "/app/docker-entrypoint.sh"]
