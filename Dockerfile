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
 && apt-get install -y --no-install-recommends nut-client iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
 && python -m pip install --no-cache-dir -r requirements.txt

COPY main.py config.py models.py extensions.py ./
COPY utils/ ./utils/
COPY services/ ./services/
COPY routes/ ./routes/
COPY templates/ ./templates/
COPY static/ ./static/

RUN mkdir -p /data
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=3)" || exit 1
CMD ["python", "main.py"]
