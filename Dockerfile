FROM python:3.11-alpine AS builder

ARG APP_UID=1000
ARG APP_GID=1000

RUN addgroup -g ${APP_GID} -S appgroup && \
    adduser -S -u ${APP_UID} -G appgroup -h /home/appuser -D appuser

# Only essential build deps
RUN apk add --no-cache \
    build-base \
    libffi-dev \
    libpcap-dev && \
    rm -rf /var/cache/apk/*

WORKDIR /app

# Copy only requirements first for better caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-alpine

ARG APP_UID=1000
ARG APP_GID=1000

RUN addgroup -g ${APP_GID} -S appgroup && \
    adduser -S -u ${APP_UID} -G appgroup -h /home/appuser -D appuser

# Only runtime dependencies
RUN apk add --no-cache \
    nut \
    libpcap \
    libcap && \
    setcap 'cap_net_raw+eip cap_net_admin+eip' /usr/local/bin/python3.11 && \
    apk del libcap && \
    mkdir -p /app /data && \
    chown -R ${APP_UID}:${APP_GID} /data /app && \
    chmod 755 /app /data && \
    rm -rf /var/cache/apk/*

WORKDIR /app

# Copy Python packages
COPY --from=builder --chown=${APP_UID}:${APP_GID} /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Copy app files
COPY --chown=${APP_UID}:${APP_GID} main.py ./
COPY --chown=${APP_UID}:${APP_GID} templates/ ./templates/
COPY --chown=${APP_UID}:${APP_GID} static/ ./static/

EXPOSE 5000
USER appuser
CMD ["python3", "main.py"]